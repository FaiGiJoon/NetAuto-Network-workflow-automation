/* Isometric device icons, drawn in code so they follow the light and dark theme.
 * Every icon is centred on (0, 0) at its foot and stands about 80 px tall.
 * Faces use the classes f-top / f-l / f-r; detail lines use ln; screens use scr. */
(function () {
  const C = Math.cos(Math.PI / 6);
  const P = (x, y, z) => [((x - y) * C).toFixed(1), ((x + y) * 0.5 - z).toFixed(1)];
  const pts = (list) => list.map((p) => p.join(",")).join(" ");
  const poly = (cls, list) => `<polygon class="${cls}" points="${pts(list)}"/>`;
  const line = (a, b, cls = "ln") => `<line class="${cls}" x1="${a[0]}" y1="${a[1]}" x2="${b[0]}" y2="${b[1]}"/>`;
  const polyline = (cls, list) => `<polyline class="${cls}" points="${pts(list)}"/>`;

  // A box with its footprint centred on (ox, oy), from height z0 to z0 + h.
  function box(w, d, h, z0 = 0, ox = 0, oy = 0) {
    const x0 = -w / 2 + ox, y0 = -d / 2 + oy, x1 = x0 + w, y1 = y0 + d, zt = z0 + h;
    return {
      svg:
        poly("f-l", [P(x0, y1, z0), P(x1, y1, z0), P(x1, y1, zt), P(x0, y1, zt)]) +
        poly("f-r", [P(x1, y0, z0), P(x1, y1, z0), P(x1, y1, zt), P(x1, y0, zt)]) +
        poly("f-top", [P(x0, y0, zt), P(x1, y0, zt), P(x1, y1, zt), P(x0, y1, zt)]),
      L: (u, v) => P(x0 + u, y1, z0 + v),   // point on the front-left face
      R: (u, v) => P(x1, y0 + u, z0 + v),   // point on the front-right face
      T: (u, v) => P(x0 + u, y0 + v, zt),   // point on the top
    };
  }

  const plinth = () => box(58, 58, 5).svg;

  const icons = {
    server() {
      const b = box(42, 42, 80);
      let s = b.svg;
      for (let v = 16; v <= 66; v += 10) s += line(b.L(6, v), b.L(36, v));
      for (let v = 16; v <= 66; v += 10) s += `<circle class="led" cx="${b.R(8, v + 3)[0]}" cy="${b.R(8, v + 3)[1]}" r="1.6"/>`;
      return s;
    },
    router() {
      const b = box(72, 46, 16);
      let s = "";
      const a1 = P(-26, -16, 16), a1t = P(-26, -16, 62);
      const a2 = P(22, -16, 16), a2t = P(22, -16, 58);
      s += line(a1, a1t, "ln thick") + line(a2, a2t, "ln thick");
      s += b.svg;
      s += `<circle class="f-top" cx="${a1t[0]}" cy="${a1t[1]}" r="3"/><circle class="f-top" cx="${a2t[0]}" cy="${a2t[1]}" r="3"/>`;
      for (let u = 40; u <= 64; u += 8) s += `<circle class="led" cx="${b.L(u, 8)[0]}" cy="${b.L(u, 8)[1]}" r="1.8"/>`;
      // wifi arcs on the top
      const c = b.T(26, 26);
      s += `<path class="ln" d="M${+c[0] - 9},${+c[1] + 1} q9,-7 18,0 M${+c[0] - 5},${+c[1] + 3} q5,-4 10,0"/>`;
      return s;
    },
    switch() {
      const b = box(96, 38, 13);
      let s = b.svg;
      for (let u = 8; u <= 84; u += 9.5) s += poly("port", [b.L(u, 3), b.L(u + 6, 3), b.L(u + 6, 9), b.L(u, 9)]);
      return s;
    },
    firewall() {
      const b = box(66, 32, 48);
      let s = b.svg;
      for (let v = 12; v < 48; v += 12) s += line(b.L(0, v), b.L(66, v));
      for (let v = 0, row = 0; v < 48; v += 12, row++) {
        for (let u = row % 2 ? 11 : 22; u < 66; u += 22) s += line(b.L(u, v), b.L(u, v + 12));
      }
      for (let v = 12; v < 48; v += 12) s += line(b.R(0, v), b.R(32, v));
      return s;
    },
    laptop(danger) {
      const b = box(66, 46, 4);
      const x0 = -33, x1 = 33, y0 = -23;
      const screen = [P(x0, y0, 4), P(x1, y0, 4), P(x1, y0 - 12, 50), P(x0, y0 - 12, 50)];
      let s = b.svg;
      s += poly("f-l", screen);
      const inset = (u, v) => P(x0 + u, y0 - 12 * (v / 46), 4 + v);
      s += poly(danger ? "scr danger" : "scr", [inset(6, 6), inset(60, 6), inset(60, 40), inset(6, 40)]);
      for (let v = 14; v <= 32; v += 6) s += line(inset(12, v), inset(v === 32 ? 34 : 50, v), danger ? "ln dg" : "ln sc");
      for (let r = 8; r <= 26; r += 6) s += line(b.T(10, r + 4), b.T(56, r + 4), "ln faint");
      return s;
    },
    attacker() { return icons.laptop(true); },
    cloud() {
      return `<g transform="translate(0,-30)">
        <path class="f-top" d="M-40,14 C-56,14 -56,-10 -38,-12 C-38,-32 -12,-38 -2,-24 C6,-42 38,-38 38,-14 C56,-14 56,14 38,14 Z"/>
        <g class="ln-g"><line x1="-18" y1="-2" x2="0" y2="-12"/><line x1="0" y1="-12" x2="20" y2="-2"/>
        <line x1="-18" y1="-2" x2="0" y2="6"/><line x1="20" y1="-2" x2="0" y2="6"/><line x1="0" y1="-12" x2="0" y2="6"/></g>
        <circle class="node-dot" cx="0" cy="-12" r="4"/><circle class="node-dot" cx="-18" cy="-2" r="4"/>
        <circle class="node-dot" cx="20" cy="-2" r="4"/><circle class="node-dot" cx="0" cy="6" r="4"/></g>`;
    },
    shield() {
      return plinth() + `<g transform="translate(0,-8)">
        <path class="f-top" d="M0,-66 L26,-56 L26,-34 C26,-18 14,-8 0,-2 C-14,-8 -26,-18 -26,-34 L-26,-56 Z"/>
        <path class="f-l" d="M0,-66 L0,-2 C-14,-8 -26,-18 -26,-34 L-26,-56 Z"/>
        <path class="ln thick" d="M-10,-34 l7,7 l13,-15" fill="none"/></g>`;
    },
    camera() {
      const pole = [P(0, 0, 0), P(0, 0, 34)];
      const b = box(18, 44, 16, 34, 0, 4);
      let s = box(26, 26, 4).svg + line(pole[0], pole[1], "ln thick") + b.svg;
      const lens = b.L(9, 8);
      s += `<ellipse class="scr" cx="${lens[0]}" cy="${lens[1]}" rx="6" ry="6.5"/><circle class="led" cx="${lens[0]}" cy="${lens[1]}" r="2.2"/>`;
      return s;
    },
    dashboard() {
      let s = box(40, 26, 3).svg + box(8, 8, 22, 3).svg;
      const x0 = -34, x1 = 34;
      const sp = (u, v) => P(x0 + u, 0, 24 + v);
      s += poly("f-l", [sp(0, 0), sp(68, 0), sp(68, 44), sp(0, 44)]);
      s += poly("scr", [sp(5, 5), sp(63, 5), sp(63, 39), sp(5, 39)]);
      s += polyline("ln sc chart", [sp(9, 12), sp(20, 22), sp(30, 16), sp(42, 30), sp(52, 24), sp(60, 34)]);
      return s;
    },
    database() {
      return `<g>
        <path class="f-l" d="M-26,-62 L-26,-8 A26,12 0 0 0 26,-8 L26,-62 Z"/>
        <path class="f-r" d="M0,-62 L26,-62 L26,-8 A26,12 0 0 1 0,4 Z"/>
        <path class="ln" d="M-26,-44 A26,12 0 0 0 26,-44 M-26,-26 A26,12 0 0 0 26,-26" fill="none"/>
        <ellipse class="f-top" cx="0" cy="-62" rx="26" ry="12"/></g>`;
    },
    backup() {
      let s = "";
      for (let i = 0; i < 3; i++) s += box(54, 44, 12, i * 17).svg;
      const b = box(54, 44, 12, 34);
      s += `<circle class="led" cx="${b.L(44, 6)[0]}" cy="${b.L(44, 6)[1]}" r="1.8"/>`;
      const c = b.T(27, 22);
      s += `<path class="ln thick" d="M${+c[0] - 8},${c[1]} a8,4 0 1 0 8,-4" fill="none"/><path class="ln thick" d="M${c[0]},${+c[1] - 7} l2,3 l-3,2" fill="none"/>`;
      return s;
    },
    git() {
      const b = box(46, 46, 46);
      let s = b.svg;
      const n1 = b.L(14, 10), n2 = b.L(14, 36), n3 = b.L(32, 28);
      s += line(n1, n2, "ln thick") + `<path class="ln thick" d="M${n3[0]},${n3[1]} Q${b.L(32, 18)[0]},${b.L(32, 18)[1]} ${b.L(14, 16)[0]},${b.L(14, 16)[1]}" fill="none"/>`;
      for (const n of [n1, n2, n3]) s += `<circle class="node-dot" cx="${n[0]}" cy="${n[1]}" r="3.4"/>`;
      return s;
    },
    script() {
      const x0 = -26;
      const sp = (u, v) => P(x0 + u, 0, v);
      let s = plinth();
      s += poly("f-l", [sp(0, 4), sp(52, 4), sp(52, 60), sp(40, 72), sp(0, 72)]);
      s += poly("f-top", [sp(40, 72), sp(52, 60), sp(40, 60)]);
      for (let v = 54, i = 0; v >= 16; v -= 9, i++) s += line(sp(8 + (i % 2) * 6, v), sp(i % 3 === 2 ? 30 : 42, v), "ln sc");
      return s;
    },
    exporter() {
      const b = box(48, 48, 26);
      let s = b.svg;
      [10, 18, 8, 14].forEach((h, i) => { s += poly("bar", [b.L(8 + i * 9, 4), b.L(14 + i * 9, 4), b.L(14 + i * 9, 4 + h), b.L(8 + i * 9, 4 + h)]); });
      const t = b.T(24, 24);
      s += `<path class="ln thick" d="M${t[0]},${+t[1] + 6} v-16 m-6,6 l6,-6 l6,6" fill="none"/>`;
      return s;
    },
    bell() {
      return plinth() + `<g transform="translate(0,-10)">
        <path class="f-top" d="M-24,-12 C-18,-18 -18,-28 -18,-40 C-18,-54 -10,-62 0,-62 C10,-62 18,-54 18,-40 C18,-28 18,-18 24,-12 Z"/>
        <path class="f-l" d="M-24,-12 C-18,-18 -18,-28 -18,-40 C-18,-54 -10,-62 0,-62 L0,-12 Z"/>
        <circle class="f-r" cx="0" cy="-6" r="5"/><circle class="led" cx="16" cy="-60" r="5"/></g>`;
    },
    chat() {
      return plinth() + `<g transform="translate(0,-14)">
        <path class="f-top" d="M-30,-58 h60 a8,8 0 0 1 8,8 v28 a8,8 0 0 1 -8,8 h-34 l-14,12 v-12 h-12 a8,8 0 0 1 -8,-8 v-28 a8,8 0 0 1 8,-8 z"/>
        <circle class="node-dot" cx="-14" cy="-36" r="3.4"/><circle class="node-dot" cx="0" cy="-36" r="3.4"/><circle class="node-dot" cx="14" cy="-36" r="3.4"/></g>`;
    },
    ticket() {
      return plinth() + `<g transform="translate(0,-12)">
        <path class="f-top" d="M-32,-60 h64 v14 a6,6 0 0 0 0,12 v20 h-64 v-20 a6,6 0 0 0 0,-12 z"/>
        <line class="ln faint" x1="14" y1="-58" x2="14" y2="-16" stroke-dasharray="3 3"/>
        <line class="ln" x1="-24" y1="-46" x2="6" y2="-46"/><line class="ln" x1="-24" y1="-36" x2="2" y2="-36"/>
        <line class="ln" x1="-24" y1="-26" x2="-4" y2="-26"/></g>`;
    },
    flow() {
      return plinth() + `<g transform="translate(0,-12)">
        <path class="ln thick" d="M-22,-44 C-6,-44 -6,-24 10,-24 M-22,-44 C-6,-44 -6,-62 10,-62" fill="none"/>
        <rect class="f-top" x="-34" y="-54" width="22" height="20" rx="5"/>
        <rect class="f-top" x="6" y="-72" width="26" height="20" rx="5"/>
        <rect class="scr" x="6" y="-34" width="26" height="20" rx="5"/>
        <circle class="node-dot" cx="-23" cy="-44" r="3"/></g>`;
    },
    ap() {
      return `<g>
        <path class="f-l" d="M-34,-12 L-34,-4 A34,16 0 0 0 34,-4 L34,-12 Z"/>
        <ellipse class="f-top" cx="0" cy="-12" rx="34" ry="16"/>
        <circle class="led" cx="0" cy="-12" r="3"/>
        <path class="ln thick" d="M-14,-40 q14,-12 28,0 M-22,-48 q22,-20 44,0 M-7,-32 q7,-6 14,0" fill="none"/></g>`;
    },
  };

  window.NETAUTO_ICON = (name) => (icons[name] || icons.server)();
})();
