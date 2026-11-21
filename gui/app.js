/* NetAuto Console: plays the workflows in scenarios.js and, when started with
 * `netauto gui`, shows the live inventory and runs validate/plan on the repo. */
(() => {
  "use strict";

  const D = window.NETAUTO;
  const ICON = window.NETAUTO_ICON;
  const $ = (s, root = document) => root.querySelector(s);
  const $$ = (s, root = document) => Array.from(root.querySelectorAll(s));
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const TOKEN = (document.querySelector('meta[name="netauto-token"]') || {}).content || "";

  // name, light colour, dark colour
  const PROTO = {
    GIT: ["Git", "#c2410c", "#fb923c"],
    SSH: ["SSH", "#4338ca", "#a5b4fc"],
    REST: ["REST", "#1f7a4d", "#5fd39a"],
    HTTPS: ["HTTPS", "#0369a1", "#5ac8f0"],
    HTTP: ["HTTP", "#3b6fb6", "#8ab4f8"],
    WEBHOOK: ["Webhook", "#a21caf", "#e879f9"],
    SNMP: ["SNMP", "#0f766e", "#5eead4"],
    ICMP: ["ICMP", "#64748b", "#a8b3c7"],
    TCP: ["TCP", "#b42318", "#ff8a80"],
    MIRROR: ["Mirror", "#8487a8", "#9a9dc4"],
    EVE: ["eve.json", "#7c3aed", "#c4a5ff"],
    AGENT: ["Wazuh agent", "#b45309", "#fbbf24"],
    SYSLOG: ["Log", "#a16207", "#facc15"],
    LOCAL: ["Decision", "#475569", "#cbd5e1"],
  };

  const byId = Object.fromEntries(D.scenarios.map((s) => [s.id, s]));
  const saved = (() => { try { return JSON.parse(localStorage.getItem("netauto-gui") || "{}"); } catch { return {}; } })();

  const state = {
    page: "workflows",
    sid: byId[saved.sid] ? saved.sid : "ids",
    idx: 0,
    playing: false,
    speed: [0.5, 1, 2, 4].includes(saved.speed) ? saved.speed : 1,
    view: saved.view === "sequence" ? "sequence" : "network",
    overview: false,
    collapsed: false,
    filter: "all",
    query: "",
    theme: saved.theme || "dark",
    look: ["tokyo-night", "catppuccin", "everforest", "gruvbox", "nord", "classic"].includes(saved.look) ? saved.look : "tokyo-night",
    leftHidden: !!saved.leftHidden,
    bottomHidden: !!saved.bottomHidden,
    progress: saved.progress || {},
    live: false,
    status: null,
  };

  let animToken = 0;
  let playTimer = null;

  const save = () => localStorage.setItem("netauto-gui", JSON.stringify({
    sid: state.sid, speed: state.speed, view: state.view, theme: state.theme, look: state.look,
    leftHidden: state.leftHidden, bottomHidden: state.bottomHidden, progress: state.progress,
  }));

  const sc = () => byId[state.sid];
  const color = (p) => (PROTO[p] || PROTO.LOCAL)[state.theme === "dark" ? 2 : 1];
  const pname = (p) => (PROTO[p] || [p])[0];
  const node = (s, id) => s.nodes.find((n) => n.id === id);
  const curEvent = () => (state.idx >= 0 ? sc().events[state.idx] : null);
  const curStep = () => (state.idx >= 0 ? sc().events[state.idx].step : 0);
  const firstOfStep = (s, step) => s.events.findIndex((e) => e.step === step);
  const fmtTime = (t) => {
    const digits = Number.isInteger(Math.round(t * 1000) / 10) ? 2 : 3;
    return t.toLocaleString("en-US", { minimumFractionDigits: digits, maximumFractionDigits: digits });
  };
  const addr = (n) => (n.ip ? n.ip : n.label);

  // ------------------------------------------------------------------ routing between nodes
  function route(s, a, b) {
    if (a === b) return [a];
    const adj = {};
    for (const [x, y] of s.links) { (adj[x] ||= []).push(y); (adj[y] ||= []).push(x); }
    const prev = { [a]: null };
    const queue = [a];
    while (queue.length) {
      const cur = queue.shift();
      if (cur === b) break;
      for (const nxt of adj[cur] || []) if (!(nxt in prev)) { prev[nxt] = cur; queue.push(nxt); }
    }
    if (!(b in prev)) return [a, b];
    const path = [];
    for (let n = b; n !== null; n = prev[n]) path.unshift(n);
    return path;
  }
  const linkKey = (a, b) => (a < b ? `${a}|${b}` : `${b}|${a}`);
  const anchor = (n) => [n.x, n.y - 24];

  function pointAt(points, frac) {
    const segs = [];
    let total = 0;
    for (let i = 1; i < points.length; i++) {
      const len = Math.hypot(points[i][0] - points[i - 1][0], points[i][1] - points[i - 1][1]);
      segs.push(len); total += len;
    }
    let d = total * frac;
    for (let i = 0; i < segs.length; i++) {
      if (d <= segs[i] || i === segs.length - 1) {
        const f = segs[i] ? Math.min(1, d / segs[i]) : 0;
        return [points[i][0] + (points[i + 1][0] - points[i][0]) * f, points[i][1] + (points[i + 1][1] - points[i][1]) * f];
      }
      d -= segs[i];
    }
    return points[0];
  }

  // ------------------------------------------------------------------ network view
  const REST_AT = 0.6;

  function packetPoints(s, ev) {
    if (ev.src === ev.dst) { const n = node(s, ev.src); return [[n.x, n.y - 108], [n.x, n.y - 108]]; }
    return route(s, ev.src, ev.dst).map((id) => anchor(node(s, id)));
  }

  function renderNet(animate) {
    const s = sc();
    const ev = curEvent();
    const step = curStep();
    const used = new Set();
    for (let i = 0; i <= state.idx; i++) {
      const p = route(s, s.events[i].src, s.events[i].dst);
      for (let j = 1; j < p.length; j++) used.add(linkKey(p[j - 1], p[j]));
    }
    const curLinks = new Set();
    const curNodes = new Set();
    if (ev) {
      const p = route(s, ev.src, ev.dst);
      p.forEach((id) => curNodes.add(id));
      for (let j = 1; j < p.length; j++) curLinks.add(linkKey(p[j - 1], p[j]));
    }
    const stepNodes = new Set();
    if (ev) s.events.filter((e) => e.step === step).forEach((e) => route(s, e.src, e.dst).forEach((id) => stepNodes.add(id)));

    let out = "";
    for (const z of s.zones || []) {
      const w = z.label.length * 6.4 + 22;
      out += `<g class="zone"><rect class="z" x="${z.x}" y="${z.y}" width="${z.w}" height="${z.h}" rx="16"/>
        <g class="zl"><rect x="${z.x + 14}" y="${z.y + z.h - 13}" width="${w}" height="24" rx="12"/>
        <text x="${z.x + 14 + w / 2}" y="${z.y + z.h + 3}" text-anchor="middle">${esc(z.label)}</text></g></g>`;
    }
    for (const [a, b] of s.links) {
      const na = anchor(node(s, a)), nb = anchor(node(s, b));
      const k = linkKey(a, b);
      const cls = curLinks.has(k) ? "link cur" : used.has(k) ? "link used" : "link";
      const style = curLinks.has(k) ? ` style="stroke:${color(ev.proto)}"` : "";
      out += `<line class="${cls}"${style} x1="${na[0]}" y1="${na[1]}" x2="${nb[0]}" y2="${nb[1]}"/>`;
    }
    for (const n of s.nodes) {
      const isEnd = ev && (n.id === ev.src || n.id === ev.dst);
      const dim = ev && !stepNodes.has(n.id) && !curNodes.has(n.id);
      out += `<g class="node${isEnd ? " end" : ""}${dim ? " dim" : ""}" data-id="${n.id}" transform="translate(${n.x},${n.y})">
        <ellipse class="base" cx="0" cy="2" rx="50" ry="25"/>
        <circle class="pulse" cx="0" cy="-24" r="40" style="transform-origin:0 -24px"/>
        ${ICON(n.icon)}
        <text class="lbl" y="44">${esc(n.label)}</text>
        ${n.ip ? `<text class="ip" y="58">${esc(n.ip)}</text>` : ""}
        <title>${esc(n.label)}${n.ip ? " " + esc(n.ip) : ""}</title></g>`;
    }
    if (ev) {
      const w = Math.max(44, ev.label.length * 7.4 + 20);
      const c = color(ev.proto);
      out += `<g class="pkt" id="pkt"><rect class="halo" x="${-w / 2 - 5}" y="-16" width="${w + 10}" height="32" rx="11" fill="${c}"/>
        <rect x="${-w / 2}" y="-11" width="${w}" height="22" rx="7" fill="${c}" stroke="var(--panel)"/>
        <text>${esc(ev.label)}</text></g>`;
    }
    const svg = $("#net");
    svg.innerHTML = out;
    svg.setAttribute("aria-label", ev ? `Network diagram. ${node(s, ev.src).label} to ${node(s, ev.dst).label}: ${ev.summary}` : "Network diagram");
    if (!ev) return Promise.resolve();
    const pts = packetPoints(s, ev);
    const pkt = $("#pkt");
    const place = (f) => { const [x, y] = pointAt(pts, f); pkt.setAttribute("transform", `translate(${x.toFixed(1)},${y.toFixed(1)})`); };
    if (!animate || REDUCED) { place(REST_AT); return Promise.resolve(); }
    return new Promise((resolve) => {
      const token = ++animToken;
      const self = ev.src === ev.dst;
      const dur = (self ? 600 : 1000) / state.speed;
      const t0 = performance.now();
      const frame = (now) => {
        if (token !== animToken) return resolve();
        const t = Math.min(1, (now - t0) / dur);
        const e = 1 - Math.pow(1 - t, 3);
        if (self) pkt.setAttribute("transform", `translate(${pts[0][0]},${(pts[0][1] + 14 * (1 - e)).toFixed(1)}) scale(${(0.6 + 0.4 * e).toFixed(2)})`);
        else place(e * REST_AT);
        if (t < 1) requestAnimationFrame(frame);
        else {
          const target = $(`#net .node[data-id="${ev.dst}"] .pulse`);
          if (target) { target.classList.remove("go"); void target.getBBox(); target.classList.add("go"); }
          resolve();
        }
      };
      requestAnimationFrame(frame);
    });
  }

  // ------------------------------------------------------------------ sequence view
  function renderSeq() {
    const s = sc();
    const ids = s.nodes.map((n) => n.id).filter((id) => s.events.some((e) => e.src === id || e.dst === id));
    const avail = ($("#seq").clientWidth || 960) - 64;
    const col = Math.max(92, Math.min(150, avail / ids.length));
    const W = col * ids.length + 40;
    const X = (id) => 20 + col * ids.indexOf(id) + col / 2;
    const ROW = 34, SEP = 30;
    let y = 8;
    let rows = "", lastStep = -1;
    s.events.forEach((e, i) => {
      if (e.step !== lastStep) {
        lastStep = e.step;
        rows += `<g class="sep"><line x1="8" x2="${W - 8}" y1="${y + 6}" y2="${y + 6}"/><text x="12" y="${y + 21}">Step ${e.step + 1} · ${esc(s.steps[e.step].title)}</text></g>`;
        y += SEP;
      }
      const c = color(e.proto);
      const cls = i === state.idx ? "row cur" : i > state.idx ? "row future" : "row";
      const x1 = X(e.src), x2 = X(e.dst), my = y + ROW / 2 + 5;
      let shape;
      if (e.src === e.dst) {
        shape = `<path d="M${x1},${my - 6} h26 v12 h-26" fill="none" stroke="${c}" stroke-width="2"/>
          <path d="M${x1 + 6},${my + 2} l-6,4 l6,4" fill="none" stroke="${c}" stroke-width="2"/>
          <text class="lab" x="${x1 + 32}" y="${my + 4}" fill="${c}" style="fill:${c}">${esc(e.label)}</text>`;
      } else {
        const dir = x2 > x1 ? 1 : -1;
        shape = `<line x1="${x1}" y1="${my}" x2="${x2 - dir * 2}" y2="${my}" stroke="${c}" stroke-width="2"/>
          <path d="M${x2 - dir * 9},${my - 5} L${x2},${my} L${x2 - dir * 9},${my + 5}" fill="${c}"/>
          <text class="lab" x="${(x1 + x2) / 2}" y="${my - 6}" text-anchor="middle" style="fill:${c}">${esc(e.label)}</text>`;
      }
      rows += `<g class="${cls}" data-idx="${i}"><rect class="band" x="4" y="${y}" width="${W - 8}" height="${ROW}" rx="6"/>
        <text x="10" y="${my + 4}">${i + 1}</text>${shape}<title>${esc(e.summary)}</title></g>`;
      y += ROW;
    });
    const H = y + 16;
    let head = "", lives = "";
    for (const id of ids) {
      const n = node(s, id);
      lives += `<line class="life" x1="${X(id)}" x2="${X(id)}" y1="0" y2="${H}"/>`;
      head += `<g class="ph"><rect x="${X(id) - col / 2 + 6}" y="4" width="${col - 12}" height="42" rx="8"/>
        <text x="${X(id)}" y="22">${esc(n.label)}</text><text class="ip" x="${X(id)}" y="37">${esc(n.ip || "")}</text></g>`;
    }
    const box = $("#seq");
    box.innerHTML = `<div class="seq-head" style="width:${W}px"><svg width="${W}" height="52" viewBox="0 0 ${W} 52">${head}</svg></div>
      <svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="Sequence diagram">${lives}${rows}</svg>`;
    const cur = $(".row.cur", box);
    if (cur) {
      const r = cur.getBBox();
      const top = r.y + 52;
      if (top < box.scrollTop + 60 || top + r.height > box.scrollTop + box.clientHeight - 20) box.scrollTop = Math.max(0, top - box.clientHeight / 2);
    }
  }

  // ------------------------------------------------------------------ side list
  function matches(s, q) {
    if (!q) return true;
    const hay = [s.name, s.full, s.program, ...(s.overview.tools || []), ...s.steps.flatMap((st) => [st.title, st.sub])].join(" ").toLowerCase();
    return q.toLowerCase().split(/\s+/).every((w) => hay.includes(w));
  }

  function renderSide() {
    const counts = { all: D.scenarios.length };
    D.groups.forEach((g) => { counts[g.id] = D.scenarios.filter((s) => s.group === g.id).length; });
    const short = { all: "All", changes: "Changes", security: "Security", monitoring: "Monitor" };
    $("#filters").innerHTML = ["all", ...D.groups.map((g) => g.id)].map((f) =>
      `<button role="tab" data-filter="${f}" aria-selected="${state.filter === f}">${short[f]} <small>${counts[f]}</small></button>`).join("");

    let html = "";
    let shown = 0;
    D.groups.forEach((g, gi) => {
      if (state.filter !== "all" && state.filter !== g.id && !state.query) return;
      const list = D.scenarios.filter((s) => s.group === g.id && matches(s, state.query));
      if (!list.length) return;
      html += `<div class="group-head"><b>${gi + 1}</b>${esc(g.label)}</div>`;
      for (const s of list) {
        shown++;
        const open = s.id === state.sid && !state.collapsed;
        const reached = state.progress[s.id] ?? -1;
        const st = reached >= s.events.length - 1 ? "full" : reached >= 0 || s.id === state.sid ? "half" : "";
        html += `<button class="wf${open ? " open" : ""}" data-sid="${s.id}" aria-expanded="${open}">
          <span class="st ${st}" aria-hidden="true"></span>
          <span class="t"><b>${esc(s.name)}</b><span>${esc(s.full)}</span></span>
          <svg class="chev" viewBox="0 0 24 24" aria-hidden="true"><path d="m9 6 6 6-6 6"/></svg></button>`;
        if (open) {
          const cur = curStep();
          html += `<ol class="steps">` + s.steps.map((stp, i) => {
            const cls = state.idx < 0 ? "" : i < cur ? "done" : i === cur ? "on" : "";
            const mark = cls === "done" ? `<svg viewBox="0 0 24 24"><path d="m5 12 5 5 9-10"/></svg>` : i + 1;
            return `<li class="${cls}" data-step="${i}" tabindex="0" role="button" aria-label="Step ${i + 1}: ${esc(stp.title)}">
              <span class="s-n">${mark}</span><span class="s-t"><b>${esc(stp.title)}</b><span>${esc(stp.sub)}</span></span></li>`;
          }).join("") + `</ol>`;
        }
      }
    });
    if (!shown) html = `<div class="side-empty">No workflow matches “${esc(state.query)}”.</div>`;
    $("#side-list").innerHTML = html;
  }

  // ------------------------------------------------------------------ header
  function renderNow() {
    const s = sc();
    const step = curStep();
    $("#now-program").textContent = s.program;
    $("#now-full").textContent = s.full;
    $("#now-cmd").textContent = state.idx < 0 ? `./${s.program} --help` : `./${s.program} --step ${curStep() + 1}`;
    $("#now-pips").innerHTML = s.steps.map((_, i) => `<i class="${state.idx >= 0 && i < step ? "done" : state.idx >= 0 && i === step ? "on" : ""}"></i>`).join("");
    $("#now-step").textContent = state.idx < 0 ? `${s.steps.length} steps. Press Play to start.` : `Step ${step + 1} of ${s.steps.length}: ${s.steps[step].title}`;
    const stage = state.idx < 0 ? -1 : s.steps[step].stage;
    $("#stage-name").textContent = stage >= 0 ? s.stages[stage] : "";
    $("#stage-boxes").innerHTML = s.stages.map((name, i) => `<span class="${i === stage ? "on" : ""}" title="${esc(name)}">${i + 1}</span>`).join("");
  }

  // ------------------------------------------------------------------ details
  function renderDetails() {
    const s = sc();
    const btn = $("#btn-overview");
    btn.setAttribute("aria-expanded", String(state.overview));
    $("span", btn).textContent = state.overview ? "Step" : "Overview";
    $("#details-title").textContent = state.overview ? "Overview" : "Step details";
    const box = $("#details");
    if (state.overview || state.idx < 0) {
      const o = s.overview;
      box.innerHTML = `<div class="d-kicker">${esc(s.program)} · ${s.steps.length} steps · ${s.events.length} events</div>
        <h2>${esc(s.full)}</h2><p>${esc(o.summary)}</p>
        <div class="h-small">Tools</div><div class="tags">${o.tools.map((t) => `<span class="tag">${esc(t)}</span>`).join("")}</div>
        <div class="h-small">Commands</div><div class="cmds">${o.commands.map((c) => `<code>${esc(c)}</code>`).join("")}</div>
        <div class="h-small">Safety built in</div><ul class="checklist">${o.safety.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>`;
      return;
    }
    const step = curStep();
    const st = s.steps[step];
    const ev = curEvent();
    const src = node(s, ev.src), dst = node(s, ev.dst);
    const c = color(ev.proto);
    const nInStep = s.events.filter((e) => e.step === step);
    const code = ev.code ? ev.code.join("\n") : ev.summary;
    const fields = [["Protocol", pname(ev.proto)], ["Source", addr(src)], ["Destination", addr(dst)], ["Time", `${fmtTime(ev.t)} s`],
      ...(ev.bytes ? [["Bytes", String(ev.bytes)]] : []), ...(ev.fields || [])];
    box.innerHTML = `<div class="d-kicker">Step ${step + 1} of ${s.steps.length}</div>
      <h2>${esc(st.title)}</h2><p class="sub">${esc(st.sub)}</p>
      ${st.body.map((p) => `<p>${esc(p)}</p>`).join("")}
      <div class="evcard" style="--c:${c}">
        <div class="top"><span class="pill">${esc(ev.label)}</span><span>${ev.src === ev.dst ? `inside ${esc(src.label)}` : `${esc(src.label)} to ${esc(dst.label)}`}</span></div>
        <pre>${esc(code)}</pre>
        <small>Event ${state.idx + 1} of ${s.events.length}, ${esc(pname(ev.proto))}${ev.bytes ? `, ${ev.bytes} bytes` : ""} · ${nInStep.indexOf(ev) + 1} of ${nInStep.length} in this step</small>
      </div>
      <dl class="kv">${fields.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl>`;
  }

  // ------------------------------------------------------------------ event flow
  function renderFlow() {
    const s = sc();
    const protos = [...new Set(s.events.map((e) => e.proto))];
    $("#legend").innerHTML = protos.map((p) => `<span style="--c:${color(p)}"><i></i>${esc(pname(p))}</span>`).join("");
    $("#counter").textContent = `${state.idx + 1} of ${s.events.length}`;
    const cur = curStep();
    let tl = "";
    s.steps.forEach((_, si) => {
      const evs = s.events.map((e, i) => [e, i]).filter(([e]) => e.step === si);
      const numCls = state.idx < 0 ? "" : si < cur ? "done" : si === cur ? "on" : "";
      tl += `<div class="tl-step" style="--n:${evs.length + 0.6}"><span class="tl-num ${numCls}">${si + 1}</span>` +
        evs.map(([e, i]) => `<button class="tl-seg ${i < state.idx ? "past" : i === state.idx ? "cur" : ""}" style="--c:${color(e.proto)}" data-idx="${i}" title="${i + 1}. ${esc(e.label)}" aria-label="Event ${i + 1}: ${esc(e.summary)}"></button>`).join("") +
        `</div>`;
    });
    const frac = state.idx < 0 ? 0 : (state.idx + 1) / s.events.length;
    $("#timeline").innerHTML = tl + `<span class="fill" style="width:calc((100% - 32px) * ${frac.toFixed(4)})"></span>`;

    $("#events").innerHTML = s.events.map((e, i) => {
      const cls = i === state.idx ? "cur" : i > state.idx ? "future" : "";
      const c = color(e.proto);
      return `<tr class="${cls}" data-idx="${i}" style="--c:${c}">
        <td><span class="no">${i + 1}</span></td><td class="num">${fmtTime(e.t)}</td>
        <td class="mono">${esc(addr(node(s, e.src)))}</td><td class="mono">${esc(addr(node(s, e.dst)))}</td>
        <td><span class="proto"><i></i>${esc(pname(e.proto))}</span></td><td class="num">${e.bytes || "–"}</td>
        <td class="sum" title="${esc(e.summary)}">${esc(e.summary)}</td></tr>`;
    }).join("");
    const wrap = $("#table-wrap");
    const row = $("tr.cur", wrap);
    if (row) {
      const head = 34;
      if (row.offsetTop - head < wrap.scrollTop) wrap.scrollTop = row.offsetTop - head;
      else if (row.offsetTop + row.offsetHeight > wrap.scrollTop + wrap.clientHeight) wrap.scrollTop = row.offsetTop + row.offsetHeight - wrap.clientHeight;
    } else if (state.idx < 0) wrap.scrollTop = 0;

    const play = $("#btn-play");
    play.classList.toggle("playing", state.playing);
    $("span", play).textContent = state.playing ? "Pause" : state.idx >= s.events.length - 1 ? "Replay" : "Play";
    play.setAttribute("aria-label", state.playing ? "Pause" : "Play");
    $("#btn-back").disabled = state.idx < 0;
    $("#btn-step").disabled = state.idx >= s.events.length - 1;
  }

  // ------------------------------------------------------------------ orchestration
  function render(animate = false) {
    renderSide();
    renderNow();
    renderDetails();
    renderFlow();
    if (state.view === "sequence") renderSeq();
    return renderNet(animate && state.view === "network");
  }

  function go(i, animate = false) {
    const s = sc();
    state.idx = Math.max(-1, Math.min(s.events.length - 1, i));
    state.progress[state.sid] = Math.max(state.progress[state.sid] ?? -1, state.idx);
    save();
    return render(animate);
  }

  function stop() {
    state.playing = false;
    clearTimeout(playTimer);
    animToken++;
  }

  function tick() {
    if (!state.playing) return;
    const s = sc();
    if (state.idx >= s.events.length - 1) { state.playing = false; renderFlow(); return; }
    go(state.idx + 1, true).then(() => {
      if (!state.playing) return;
      playTimer = setTimeout(tick, (REDUCED ? 900 : 700) / state.speed);
    });
  }

  function togglePlay() {
    if (state.playing) { stop(); renderFlow(); return; }
    if (state.idx >= sc().events.length - 1) state.idx = -1;
    state.playing = true;
    tick();
  }

  const manual = (i, animate = false) => { stop(); return go(i, animate); };

  function selectScenario(id) {
    if (!byId[id]) return;
    stop();
    if (id === state.sid) { state.collapsed = !state.collapsed; renderSide(); return; }
    state.sid = id;
    state.collapsed = false;
    state.overview = false;
    go(0);
  }

  function setView(v) {
    state.view = v;
    $$(".seg button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.view === v)));
    $("#net").toggleAttribute("hidden", v !== "network");
    $("#seq").hidden = v !== "sequence";
    save();
    render();
  }

  function setTheme(t) {
    state.theme = t;
    document.documentElement.dataset.theme = t;
    $("#theme-btn").setAttribute("aria-label", t === "dark" ? "Switch to light mode" : "Switch to dark mode");
    save();
    if (state.page === "workflows") render();
  }

  // Omarchy themes (tiling-window look) or the original Classic look.
  const LOOKS = ["tokyo-night", "catppuccin", "everforest", "gruvbox", "nord", "classic"];
  const LOOK_NAMES = { "tokyo-night": "Tokyo Night", catppuccin: "Catppuccin", everforest: "Everforest", gruvbox: "Gruvbox", nord: "Nord", classic: "Classic" };
  function applyLook() {
    const root = document.documentElement;
    root.dataset.style = state.look === "classic" ? "classic" : "omarchy";
    root.dataset.palette = state.look;
    const next = LOOKS[(LOOKS.indexOf(state.look) + 1) % LOOKS.length];
    $("#style-btn").setAttribute("aria-label", `Theme: ${LOOK_NAMES[state.look]}. Switch to ${LOOK_NAMES[next]}`);
    $("#style-btn").title = `Theme: ${LOOK_NAMES[state.look]} (Y for ${LOOK_NAMES[next]})`;
  }
  function setLook(v) {
    state.look = LOOKS.includes(v) ? v : "tokyo-night";
    applyLook();
    save();
    toast(`Theme: ${LOOK_NAMES[state.look]}${state.look !== "classic" && state.theme === "light" ? " (light: Latte)" : ""}`);
    if (state.page === "workflows") render();
  }
  const cycleLook = () => setLook(LOOKS[(LOOKS.indexOf(state.look) + 1) % LOOKS.length]);
  let toastTimer = null;
  function toast(text) {
    const el = $("#toast");
    el.textContent = text;
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.hidden = true; }, 1600);
  }
  function tickClock() {
    const d = new Date();
    $("#clock").textContent = d.toLocaleDateString(undefined, { weekday: "short", day: "numeric", month: "short" }) + "  " +
      d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  }

  function applyLayout() {
    const w = $("#work");
    w.classList.toggle("no-left", state.leftHidden);
    w.classList.toggle("no-bottom", state.bottomHidden);
    $("#btn-left").setAttribute("aria-pressed", String(!state.leftHidden));
    $("#btn-bottom").setAttribute("aria-pressed", String(!state.bottomHidden));
    save();
  }

  function downloadCsv() {
    const s = sc();
    const q = (v) => `"${String(v).replace(/"/g, '""')}"`;
    const lines = [["no", "time_s", "source", "destination", "protocol", "bytes", "step", "summary"].join(",")];
    s.events.forEach((e, i) => lines.push([i + 1, e.t, q(addr(node(s, e.src))), q(addr(node(s, e.dst))), e.proto, e.bytes, q(s.steps[e.step].title), q(e.summary)].join(",")));
    const url = URL.createObjectURL(new Blob([lines.join("\n") + "\n"], { type: "text/csv" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: `${s.program}-events.csv` });
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // ------------------------------------------------------------------ pages
  function setPage(p) {
    if (!["workflows", "tools", "inventory", "plan", "programs", "diagnostics", "settings"].includes(p)) p = "workflows";
    if (p !== "workflows") stop();
    state.page = p;
    $$(".tabs button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.page === p)));
    $$(".page").forEach((el) => { el.hidden = el.id !== `page-${p}`; });
    if (location.hash.slice(1) !== p) history.replaceState(null, "", p === "workflows" ? location.pathname : `#${p}`);
    if (p === "workflows") render();
    if (p === "inventory") loadInventory();
    if (p === "plan") $("#plan-offline").hidden = state.live;
    if (p === "plan") $$("#page-plan button.primary").forEach((b) => { b.disabled = !state.live; });
    if (p === "programs") renderPrograms();
    $$(".live-only-note").forEach((el) => { el.hidden = state.live; });
    const extra = window.NETAUTO_PAGES && window.NETAUTO_PAGES[p];
    if (extra) extra();
  }

  async function api(path, body) {
    const headers = { "X-NetAuto-Token": TOKEN };
    const opts = body === undefined ? { headers } : { method: "POST", headers: { ...headers, "Content-Type": "application/json" }, body: JSON.stringify(body) };
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 20000);
    try {
      const r = await fetch(path, { ...opts, signal: ctrl.signal });
      const data = await r.json();
      if (!r.ok && data && data.errors) { const err = new Error(data.errors.join(" ")); err.status = r.status; err.data = data; throw err; }
      return data;
    } finally { clearTimeout(t); }
  }

  async function checkLive() {
    if (location.protocol === "file:") return setConn(false);
    try {
      state.status = await api("api/status");
      setConn(true);
    } catch { setConn(false); }
  }

  function setConn(live) {
    state.live = live;
    const el = $("#conn");
    el.classList.toggle("live", live);
    $("#conn-text").textContent = live ? `Live · netauto ${state.status.version}` : "Demo mode";
    el.title = live ? `Repo: ${state.status.repo}` : "Start with `netauto gui` for live data, checks and plans";
    if (state.page !== "workflows") setPage(state.page);
  }

  async function loadInventory() {
    let data = D.inventorySnapshot, source = "A snapshot of the example data. Start the console with netauto gui to see your own repo.";
    if (state.live) {
      try {
        const live = await api("api/inventory");
        if (live.ok) { data = live; source = `Live from ${state.status.repo}`; }
        else source = `Could not read the data: ${live.errors.join("; ")}`;
      } catch { /* keep the snapshot */ }
    }
    $("#inv-source").textContent = source;
    const vlanCount = data.sites.reduce((n, s) => n + s.vlans.length, 0);
    const perDev = {};
    data.sites.forEach((s) => s.vlans.forEach((v) => (v.devices || []).forEach((d) => { perDev[d] = (perDev[d] || 0) + 1; })));
    $("#inv-stats").innerHTML = [[data.devices.length, "Devices"], [data.sites.length, "Sites"], [vlanCount, "VLANs"],
      [data.devices.filter((d) => d.l3).length, "Gateways"]].map(([n, l]) => `<div class="stat"><b>${n}</b><span>${l}</span></div>`).join("");
    $("#inv-devices").innerHTML = `<thead><tr><th>Name</th><th>Site</th><th>Platform</th><th>Management IP</th><th>Role</th><th>Trunk ports</th><th>VLANs</th></tr></thead><tbody>` +
      data.devices.map((d) => `<tr><td><b>${esc(d.name)}</b></td><td>${esc(d.site)}</td>
        <td><span class="badge ${d.platform === "routeros" ? "ros" : "ios"}">${d.platform === "routeros" ? "RouterOS" : d.platform === "ios" ? "Cisco IOS" : esc(d.platform)}</span></td>
        <td class="mono">${esc(d.mgmt_ip)}</td><td>${d.l3 ? '<span class="badge ok">Gateway (L3)</span>' : "Switching (L2)"}</td>
        <td class="mono">${esc((d.trunk_ports || []).join(", "))}</td><td class="mono">${perDev[d.name] || 0}</td></tr>`).join("") + `</tbody>`;
    $("#inv-sites").innerHTML = data.sites.map((s) => `<div class="card"><div class="card-head"><span class="dash"></span>Site ${esc(s.site)}
        <span class="right">${esc(s.file)} · code ${esc(s.code)}</span></div><div class="table-scroll"><table class="grid-table">
        <thead><tr><th>ID</th><th>Name</th><th>Description</th><th>Subnet</th><th>Gateway</th><th>DHCP</th><th>Devices</th></tr></thead><tbody>` +
      s.vlans.map((v) => `<tr><td class="mono"><b>${esc(v.id)}</b></td><td class="mono">${esc(v.name)}</td><td>${esc(v.description || "")}</td>
        <td class="mono">${esc(v.subnet)}</td><td class="mono">${esc(v.gateway || "–")}${v.gateway_device ? ` <span class="muted">on ${esc(v.gateway_device)}</span>` : ""}</td>
        <td class="mono">${v.dhcp ? `${esc(v.dhcp.start)} – ${esc(v.dhcp.end)}` : "–"}</td><td class="mono">${esc((v.devices || []).join(", "))}</td></tr>`).join("") +
      `</tbody></table></div></div>`).join("");
  }

  async function runValidate() {
    const out = $("#validate-result");
    out.innerHTML = `<span class="muted">Running checks…</span>`;
    try {
      const r = await api("api/validate", {});
      out.innerHTML = r.ok
        ? `<div class="okline"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="m5 12 5 5 9-10"/></svg>${esc(r.summary)}</div>`
        : `<div class="badline">${esc(r.summary)}</div><ul>${r.errors.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>`;
    } catch (e) { out.innerHTML = `<div class="badline">${esc(e.status ? e.message : "The server did not answer: " + e.message)}</div>`; }
  }

  function describeVlan(v) {
    const extra = [];
    if (v.l3) extra.push(`gateway ${v.l3.gateway}/${v.l3.prefixlen}`);
    if (v.dhcp) extra.push(`DHCP ${v.dhcp.start}-${v.dhcp.end}`);
    return `VLAN ${v.id} ${v.name}${extra.length ? ` (${extra.join(", ")})` : ""}`;
  }

  async function runPlan(base) {
    const out = $("#plan-result");
    out.innerHTML = `<div class="card"><p class="muted" style="margin-top:14px">Building the plan…</p></div>`;
    try {
      const r = await api("api/plan", { base });
      if (!r.ok) { out.innerHTML = `<div class="card"><div class="card-head"><span class="dash"></span>Plan</div><div class="result"><div class="badline">The plan could not be built.</div><ul>${r.errors.map((e) => `<li>${esc(e)}</li>`).join("")}</ul></div></div>`; return; }
      const devs = Object.entries(r.devices);
      let html = `<div class="card"><div class="card-head"><span class="dash"></span>Network change plan<span class="right">from ${esc(r.base || "nothing")} to ${esc(r.target)}</span></div>`;
      html += r.warnings.map((w) => `<div class="warnbox">${esc(w)}</div>`).join("");
      html += devs.length ? `<p class="muted">${devs.length} device(s) change. Read the commands below before you merge.</p>` : `<p class="muted">No changes. Nothing will be pushed.</p>`;
      html += `</div>`;
      html += devs.map(([name, d]) => `<div class="card"><div class="card-head"><span class="dash"></span><span class="devname">${esc(name)}</span>
          <span class="right">${d.platform === "routeros" ? "RouterOS" : "Cisco IOS"} · ${esc(d.mgmt_ip)}</span></div>
        <ul class="dev-changes">${d.add.map((v) => `<li class="add"><b>ADD</b>${esc(describeVlan(v))}</li>`).join("")}
          ${d.change.map((c) => `<li class="change"><b>CHANGE</b>${esc(describeVlan(c.old))} → ${esc(describeVlan(c.new))}</li>`).join("")}
          ${d.remove.map((v) => `<li class="remove"><b>REMOVE</b>${esc(describeVlan(v))}</li>`).join("")}</ul>
        <pre class="code"><button class="btn copy" data-copy>Copy</button>${esc(d.commands.join("\n"))}</pre></div>`).join("");
      out.innerHTML = html;
    } catch (e) { out.innerHTML = `<div class="card"><p class="badline">${esc(e.status ? e.message : "The server did not answer: " + e.message)}</p></div>`; }
  }

  function renderPrograms() {
    const cards = D.scenarios.map((s) => `<div class="card prog"><div class="card-head"><span class="dash"></span>${esc(D.groups.find((g) => g.id === s.group).label)}</div>
      <h3>${esc(s.program)}</h3><div class="wfname">${esc(s.full)}</div><p>${esc(s.overview.summary)}</p>
      <div class="cmds">${s.overview.commands.map((c) => `<code>${esc(c)}</code>`).join("")}</div>
      <div class="actions"><button class="btn primary" data-play="${s.id}"><svg viewBox="0 0 24 24"><path d="M7 4v16l13-8z"/></svg>Play the workflow</button>
        ${s.program === "netauto" ? `<button class="btn" data-goto="plan">Check and plan</button>` :
          `<button class="btn" data-check="${s.program}" data-action="check" ${state.live ? "" : "disabled title='Needs the local server'"}>Run check</button>`}
        ${s.program === "netops-soc" ? `<button class="btn" data-check="netops-soc" data-action="test" ${state.live ? "" : "disabled"}>Test with a sample alert</button>` : ""}</div></div>`);
    $("#programs").innerHTML = cards.join("");
  }

  // ------------------------------------------------------------------ events
  function bind() {
    $$(".tabs button, .brand").forEach((b) => b.addEventListener("click", (e) => { e.preventDefault(); setPage(b.dataset.page); }));
    window.addEventListener("hashchange", () => setPage(location.hash.slice(1)));
    $("#theme-btn").addEventListener("click", () => setTheme(state.theme === "dark" ? "light" : "dark"));
    $("#style-btn").addEventListener("click", cycleLook);
    $$(".seg button").forEach((b) => b.addEventListener("click", () => setView(b.dataset.view)));

    $("#side-list").addEventListener("click", (e) => {
      const wf = e.target.closest(".wf");
      if (wf) return selectScenario(wf.dataset.sid);
      const li = e.target.closest("li[data-step]");
      if (li) manual(firstOfStep(sc(), +li.dataset.step), true);
    });
    $("#side-list").addEventListener("keydown", (e) => {
      const li = e.target.closest("li[data-step]");
      if (li && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); e.stopPropagation(); manual(firstOfStep(sc(), +li.dataset.step), true); }
    });
    $("#filters").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-filter]");
      if (b) { state.filter = b.dataset.filter; renderSide(); }
    });
    $("#search").addEventListener("input", (e) => { state.query = e.target.value.trim(); renderSide(); });
    $("#search").addEventListener("keydown", (e) => {
      if (e.key === "Escape") { e.target.value = ""; state.query = ""; renderSide(); e.target.blur(); }
      if (e.key === "Enter") {
        const first = D.scenarios.find((s) => matches(s, state.query));
        if (first && first.id !== state.sid) selectScenario(first.id);
        e.target.blur();
      }
    });

    $("#btn-play").addEventListener("click", togglePlay);
    $("#btn-step").addEventListener("click", () => manual(state.idx + 1, true));
    $("#btn-back").addEventListener("click", () => manual(state.idx - 1));
    $("#btn-reset").addEventListener("click", () => manual(-1));
    $("#speed").value = String(state.speed);
    $("#speed").addEventListener("change", (e) => { state.speed = +e.target.value; save(); });
    $("#btn-download").addEventListener("click", downloadCsv);
    $("#btn-overview").addEventListener("click", () => { state.overview = !state.overview; renderDetails(); });
    $("#events").addEventListener("click", (e) => { const tr = e.target.closest("tr[data-idx]"); if (tr) manual(+tr.dataset.idx, true); });
    $("#timeline").addEventListener("click", (e) => { const b = e.target.closest("[data-idx]"); if (b) manual(+b.dataset.idx, true); });
    $("#seq").addEventListener("click", (e) => { const g = e.target.closest("[data-idx]"); if (g) manual(+g.dataset.idx); });

    $("#btn-left").addEventListener("click", () => { state.leftHidden = !state.leftHidden; applyLayout(); });
    $("#btn-bottom").addEventListener("click", () => { state.bottomHidden = !state.bottomHidden; applyLayout(); });
    $("#btn-full").addEventListener("click", toggleFull);
    $("#btn-keys").addEventListener("click", () => $("#keys").showModal());

    $("#btn-inv-reload").addEventListener("click", loadInventory);
    $("#btn-validate").addEventListener("click", runValidate);
    $("#plan-form").addEventListener("submit", (e) => { e.preventDefault(); runPlan($("#plan-base").value.trim()); });
    $$(".quick button").forEach((b) => b.addEventListener("click", () => { $("#plan-base").value = b.dataset.ref; if (state.live) runPlan(b.dataset.ref); }));
    $("#plan-result").addEventListener("click", (e) => {
      const b = e.target.closest("[data-copy]");
      if (!b) return;
      const text = b.parentElement.textContent.replace(/^Copy/, "");
      navigator.clipboard?.writeText(text).then(() => { b.textContent = "Copied"; setTimeout(() => { b.textContent = "Copy"; }, 1200); });
    });
    $("#programs").addEventListener("click", (e) => {
      const chk = e.target.closest("[data-check]");
      if (chk) { window.NETAUTO_PAGES.runProgram(chk.dataset.check, chk.dataset.action); return; }
      const go = e.target.closest("[data-goto]");
      if (go) { setPage(go.dataset.goto); return; }
      const b = e.target.closest("[data-play]");
      if (!b) return;
      setPage("workflows");
      if (b.dataset.play !== state.sid) selectScenario(b.dataset.play);
      state.idx = -1; togglePlay();
    });

    document.addEventListener("keydown", (e) => {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const typing = /^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement?.tagName);
      if (typing || $("#keys").open) return;
      if (e.key === "?") { $("#keys").showModal(); return; }
      if (e.key.toLowerCase() === "t") return setTheme(state.theme === "dark" ? "light" : "dark");
      if (e.key.toLowerCase() === "y") return cycleLook();
      const pages = ["workflows", "tools", "inventory", "plan", "programs", "diagnostics", "settings"];
      if (/^[1-7]$/.test(e.key)) { e.preventDefault(); return setPage(pages[+e.key - 1]); }
      if (state.page !== "workflows") return;
      const order = D.scenarios.map((s) => s.id);
      const keyMap = {
        " ": togglePlay,
        ArrowRight: () => manual(state.idx + 1, true),
        ArrowLeft: () => manual(state.idx - 1),
        r: () => manual(-1),
        n: () => setView("network"),
        s: () => setView("sequence"),
        j: () => selectScenario(order[(order.indexOf(state.sid) + 1) % order.length]),
        k: () => selectScenario(order[(order.indexOf(state.sid) - 1 + order.length) % order.length]),
        l: () => { state.leftHidden = !state.leftHidden; applyLayout(); },
        b: () => { state.bottomHidden = !state.bottomHidden; applyLayout(); },
        f: toggleFull,
        "/": () => $("#search").focus(),
      };
      const fn = keyMap[e.key] || keyMap[e.key.toLowerCase()];
      if (!fn) return;
      if (e.target.closest && e.target.closest("button") && (e.key === " ")) e.target.blur();
      e.preventDefault();
      fn();
    });
  }

  function toggleFull() {
    if (document.fullscreenElement) document.exitFullscreen?.();
    else document.documentElement.requestFullscreen?.().catch(() => {});
  }

  // ------------------------------------------------------------------ start
  document.documentElement.dataset.theme = state.theme;
  applyLook();
  tickClock();
  setInterval(tickClock, 15000);
  $("#theme-btn").setAttribute("aria-label", state.theme === "dark" ? "Switch to light mode" : "Switch to dark mode");
  bind();
  applyLayout();
  $$(".seg button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.view === state.view)));
  $("#net").toggleAttribute("hidden", state.view !== "network");
  $("#seq").hidden = state.view !== "sequence";
  setPage(location.hash.slice(1) || "workflows");
  checkLive();
  // Report browser errors to the debug log on the Diagnostics page.
  const reportError = (message, detail) => {
    if (!state.live) return;
    fetch("api/debug/client", { method: "POST", headers: { "Content-Type": "application/json", "X-NetAuto-Token": TOKEN },
      body: JSON.stringify({ message: String(message).slice(0, 500), detail: String(detail || "").slice(0, 4000) }) }).catch(() => {});
  };
  window.addEventListener("error", (e) => reportError(e.message, `${e.filename}:${e.lineno}:${e.colno} ${(e.error && e.error.stack) || ""}`));
  window.addEventListener("unhandledrejection", (e) => reportError(`Unhandled: ${(e.reason && e.reason.message) || e.reason}`, e.reason && e.reason.stack));

  window.NETAUTO_APP = { state, go: manual, select: selectScenario, setView, setTheme, setLook, setPage, toast, api, esc, $, $$, color, pname, PROTO };
})();
