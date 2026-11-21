"""The automated network engineer: one check-up of your network, with a score,
findings, and fixes you can apply.

What it checks:
  Connectivity  gateway and internet ping (loss, latency), DNS lookups and the
                DNS servers in use, a TCP connection to the outside world
  Wi-Fi         the network you are on: signal, security, channel congestion,
                and the best 2.4 GHz channel (1, 6 or 11)
  Devices       every device on your subnet (nmap), risky open ports (Telnet,
                FTP, RDP, VNC ...), and devices that were not there last time
  MikroTik      management services, UPnP, firewall input rule, SSH crypto,
                neighbour discovery and MAC server exposure, the default admin
                user, interface errors and RouterOS updates

Fixes only exist for safe MikroTik settings, are shown first (preview), and are
applied only when you confirm and NETOPS_DRY_RUN is false.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import time
from datetime import datetime
from pathlib import Path

import _toolkit as tk

WEIGHT = {"bad": 15, "warn": 6, "info": 0, "good": 0}
RISKY_PORTS = {
    21: ("warn", "FTP", "FTP sends passwords in clear text. Turn it off, or use SFTP."),
    23: ("bad", "Telnet", "Telnet sends passwords in clear text. Turn it off and use SSH."),
    80: ("info", "HTTP", "A web page without encryption. Fine for a printer; for a router admin page prefer HTTPS."),
    445: ("info", "SMB file sharing", "Normal for Windows PCs and NAS. Make sure it is never forwarded to the internet."),
    3389: ("warn", "Remote Desktop", "Never forward RDP to the internet; use a VPN. Keep Windows updated."),
    5900: ("warn", "VNC", "VNC is often weakly protected. Use a password and only reach it over a VPN."),
    8291: ("info", "MikroTik Winbox", "Limit Winbox to your management network (/ip service set winbox address=...)."),
    8728: ("warn", "MikroTik API (plain)", "The plain API sends passwords unencrypted. Disable it and use api-ssl or REST over HTTPS."),
}


class Report:
    def __init__(self, job):
        self.job = job
        self.findings: list[dict] = []

    def add(self, area: str, severity: str, title: str, detail: str = "", fix: str = "", action: dict | None = None):
        self.findings.append({"area": area, "severity": severity, "title": title, "detail": detail,
                              "fix": fix, "action": action})
        mark = {"bad": "FAIL", "warn": "WARN", "info": "info", "good": "OK  "}[severity]
        self.job.log(f"{mark}  {title}" + (f": {detail}" if detail else ""))

    def score(self) -> int:
        return max(0, 100 - sum(WEIGHT[f["severity"]] for f in self.findings))


# ------------------------------------------------------------------ connectivity

def _ping(target: str, count: int = 4) -> dict:
    try:
        cmd = tk.ping_cmd(target, count)
        r = tk.run(cmd, timeout=10 + count * 3)
        return tk.parse_ping((r.stdout or "") + (r.stderr or ""))
    except Exception as exc:                                    # noqa: BLE001
        return {"loss_percent": None, "error": str(exc)}


def dns_servers() -> list[str]:
    servers: list[str] = []
    try:
        if tk.IS_WINDOWS:
            out = tk.run(["ipconfig", "/all"], timeout=15).stdout
            servers = parse_ipconfig_dns(out)
        elif tk.IS_MAC:
            out = tk.run(["scutil", "--dns"], timeout=10).stdout
            servers = re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", out)
        else:
            text = Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="replace")
            servers = re.findall(r"^\s*nameserver\s+(\S+)", text, re.M)
    except Exception:                                           # noqa: BLE001
        pass
    seen = []
    for s in servers:
        if s not in seen:
            seen.append(s)
    return seen[:6]


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.split("%")[0])
        return True
    except ValueError:
        return False


def parse_ipconfig_dns(text: str) -> list[str]:
    """ipconfig /all, any language: 'DNS Servers . . . : 1.1.1.1' plus continuation lines with only an address."""
    servers, taking = [], False
    for line in text.splitlines():
        stripped = line.strip()
        if taking and _is_ip(stripped):
            servers.append(stripped.split("%")[0])
            continue
        m = re.match(r"^\s*(.+?)[\s.]*:\s(.*)$", line)
        taking = bool(m and re.search(r"dns.?server", m.group(1), re.I))
        if taking and _is_ip(m.group(2).strip()):
            servers.append(m.group(2).strip().split("%")[0])
    return servers


def _resolve(name: str) -> tuple[str, float | None, str]:
    t0 = time.time()
    try:
        socket.getaddrinfo(name, 443, proto=socket.IPPROTO_TCP)
        return name, (time.time() - t0) * 1000, ""
    except OSError as exc:
        return name, None, str(exc)


def _tcp(host: str, port: int, timeout: float = 5) -> float | None:
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return (time.time() - t0) * 1000
    except OSError:
        return None


def check_connectivity(rep: Report, info: dict) -> None:
    rep.job.log("== Connectivity")
    gw = info.get("gateway")
    if not info.get("local_ip"):
        rep.add("Connectivity", "bad", "No network connection", "This computer has no IP address with a route out.",
                "Check the cable or Wi-Fi connection.")
        return
    if gw:
        p = _ping(gw)
        loss, avg = p.get("loss_percent"), p.get("avg_ms")
        if loss is None:
            rep.add("Connectivity", "warn", f"Could not ping the gateway {gw}", p.get("error", ""),
                    "Some routers ignore ping. If the internet works, this is fine.")
        elif loss >= 50:
            rep.add("Connectivity", "bad", f"Gateway {gw} drops {loss:.0f}% of pings", "The link to your router is unreliable.",
                    "On Wi-Fi: move closer or change the channel. On a cable: try another cable or switch port.")
        elif loss > 0:
            rep.add("Connectivity", "warn", f"Gateway {gw} drops {loss:.0f}% of pings", f"average {avg} ms",
                    "Packet loss to your own router usually means Wi-Fi interference or a bad cable.")
        elif avg is not None and avg > 20:
            rep.add("Connectivity", "warn", f"Gateway {gw} is slow to answer ({avg} ms)", "A router on the local network should answer within a few ms.",
                    "High latency to the router is usually Wi-Fi congestion. See the Wi-Fi findings.")
        else:
            rep.add("Connectivity", "good", f"Gateway {gw} answers", f"{avg} ms, no loss")
    else:
        rep.add("Connectivity", "warn", "No default gateway found", "", "Check the network settings of this computer.")

    results = {t: _ping(t) for t in ("1.1.1.1", "8.8.8.8")}
    ok = {t: r for t, r in results.items() if r.get("loss_percent") is not None and r["loss_percent"] < 100}
    if not ok:
        rep.add("Connectivity", "bad", "No internet: 1.1.1.1 and 8.8.8.8 do not answer", "",
                "Check the WAN link of the router, the modem, or your provider.")
    else:
        loss = max(r["loss_percent"] for r in ok.values())
        avg = min((r["avg_ms"] for r in ok.values() if r.get("avg_ms") is not None), default=None)
        if loss > 0:
            rep.add("Connectivity", "warn", f"Internet packet loss {loss:.0f}%", f"best latency {avg} ms",
                    "If the gateway has no loss but the internet has, the problem is the WAN or your provider.")
        elif avg is not None and avg > 80:
            rep.add("Connectivity", "warn", f"Internet latency is high ({avg} ms)", "", "Check for big downloads or a busy uplink; consider queues (QoS) on the router.")
        else:
            rep.add("Connectivity", "good", "Internet reachable", f"{avg} ms to the nearest public DNS, no loss")

    servers = dns_servers()
    with concurrent.futures.ThreadPoolExecutor(3) as pool:
        lookups = list(pool.map(_resolve, ("github.com", "cloudflare.com", "microsoft.com")))
    failed = [n for n, ms, err in lookups if ms is None]
    times = [ms for n, ms, err in lookups if ms is not None]
    server_text = f"DNS servers: {', '.join(servers)}" if servers else "DNS servers: unknown"
    if len(failed) == len(lookups):
        rep.add("DNS", "bad", "DNS lookups fail", f"{server_text}. {lookups[0][2]}",
                "Set a working DNS server (your router, or 1.1.1.1 / 9.9.9.9).")
    elif failed:
        rep.add("DNS", "warn", f"Some DNS lookups fail: {', '.join(failed)}", server_text)
    elif max(times) > 300:
        rep.add("DNS", "warn", f"DNS is slow ({max(times):.0f} ms)", server_text,
                "Use a faster resolver, or turn on the DNS cache of your router.")
    else:
        rep.add("DNS", "good", "DNS works", f"{max(times):.0f} ms at worst. {server_text}")
    if ok:
        ms = _tcp("github.com", 443)
        if ms is None:
            rep.add("Connectivity", "warn", "HTTPS to github.com does not connect", "Ping works but TCP 443 does not.",
                    "A firewall or proxy blocks outgoing HTTPS.")
        else:
            rep.add("Connectivity", "good", "HTTPS works", f"TCP connect to github.com:443 in {ms:.0f} ms")


# ------------------------------------------------------------------ Wi-Fi

def check_wifi(rep: Report) -> dict:
    rep.job.log("== Wi-Fi")
    try:
        cmd = tk.wifi_cmd()
    except tk.BadInput as exc:
        rep.add("Wi-Fi", "info", "Wi-Fi not checked", str(exc))
        return {}
    r = tk.run(cmd, timeout=45)
    text = (r.stdout or "") + (r.stderr or "")
    nets = tk.parse_wifi(text)
    current = tk.connected_ssid_windows()
    for n in nets:
        n["connected"] = n["connected"] or (current is not None and n["ssid"] == current)
    if not nets:
        rep.add("Wi-Fi", "info", "No Wi-Fi networks found", tk.wifi_hint(text))
        return {"networks": []}
    mine = sorted((n for n in nets if n["connected"]), key=lambda n: -(n["signal"] or 0))
    summary = tk.wifi_summary(nets)
    if not mine:
        rep.add("Wi-Fi", "info", "This computer is not on Wi-Fi", f"{summary['networks']} networks around you")
        return {"networks": nets, "summary": summary}
    me = mine[0]
    sig = me["signal"] or 0
    if sig < 35:
        rep.add("Wi-Fi", "bad", f"Weak signal on {me['ssid']} ({sig}%)", f"channel {me['channel']}, {me['band']}",
                "Move closer to the access point, remove obstacles, or add an access point or mesh node.")
    elif sig < 55:
        rep.add("Wi-Fi", "warn", f"Moderate signal on {me['ssid']} ({sig}%)", f"channel {me['channel']}, {me['band']}",
                "Expect lower speeds. An access point closer to where you work helps most.")
    else:
        rep.add("Wi-Fi", "good", f"Good signal on {me['ssid']} ({sig}%)", f"channel {me['channel']}, {me['band']}")
    sec = me["security"] or "Open"
    if re.search(r"\b(open|wep|none)\b", sec, re.I):
        rep.add("Wi-Fi", "bad", f"{me['ssid']} is not encrypted properly ({sec})", "Anyone nearby can read your traffic.",
                "Set the network to WPA2-Personal (AES) or WPA3.")
    elif re.search(r"tkip|wpa-personal\b|\bwpa\b(?!2|3)", sec, re.I):
        rep.add("Wi-Fi", "warn", f"{me['ssid']} uses old security ({sec})", "", "Switch to WPA2 with AES (CCMP), or WPA3.")
    else:
        rep.add("Wi-Fi", "good", f"Security: {sec}")
    ch = me["channel"]
    if ch and ch <= 14:
        def crowd(c):
            return sum(1 for n in nets if n["channel"] and n["channel"] <= 14 and abs(n["channel"] - c) < 5 and n["ssid"] != me["ssid"])
        here = crowd(ch)
        best = min((1, 6, 11), key=crowd)
        if ch not in (1, 6, 11):
            rep.add("Wi-Fi", "warn", f"Channel {ch} overlaps two clean channels", f"{here} other networks interfere",
                    f"Use channel {best} (1, 6 and 11 do not overlap; {best} is the quietest here: {crowd(best)} networks).")
        elif crowd(best) + 2 <= here:
            rep.add("Wi-Fi", "warn", f"Channel {ch} is crowded ({here} other networks)", "",
                    f"Switch the access point to channel {best} ({crowd(best)} networks).")
        else:
            rep.add("Wi-Fi", "good", f"Channel {ch} is a good choice", f"{here} other networks nearby")
        if any(n["ssid"] == me["ssid"] and (n["channel"] or 0) > 14 for n in nets):
            rep.add("Wi-Fi", "info", f"{me['ssid']} also has 5 GHz", "", "5 GHz is faster and less crowded at short range; let devices prefer it (band steering).")
    if summary["open_or_wep"]:
        rep.add("Wi-Fi", "info", f"Open or WEP networks nearby: {', '.join(summary['open_or_wep'][:5])}",
                "", "Do not connect to these without a VPN.")
    return {"networks": nets, "summary": summary}


# ------------------------------------------------------------------ devices on the LAN

def baseline_path() -> Path:
    from _runtime import default_state_dir
    path = default_state_dir()
    path.mkdir(parents=True, exist_ok=True)
    return path / "known-devices.json"


def load_baseline() -> dict:
    try:
        return json.loads(baseline_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_baseline(devices: list[dict]) -> int:
    known = load_baseline()
    now = datetime.now().isoformat(timespec="seconds")
    for d in devices:
        key = (d.get("mac") or d.get("ip") or "").lower()
        if key and key not in known:
            known[key] = {"ip": d.get("ip"), "mac": d.get("mac"), "vendor": d.get("vendor"), "hostname": d.get("hostname"),
                          "first_seen": now}
    baseline_path().write_text(json.dumps(known, indent=2), encoding="utf-8")
    return len(known)


def check_devices(rep: Report, info: dict, out_dir: Path) -> list[dict]:
    rep.job.log("== Devices on your network")
    subnet = info.get("suggested_subnet")
    nmap = tk.find_tool("nmap")
    if not nmap or not subnet:
        rep.add("Devices", "info", "Device scan skipped", "nmap is not installed" if not nmap else "no local IPv4 network",
                tk.hint("nmap") if not nmap else "")
        return []
    if not ipaddress.ip_network(subnet).is_private:
        rep.add("Devices", "info", "Device scan skipped", f"{subnet} is not a private network")
        return []
    xml1 = out_dir / f"checkup-hosts-{os.getpid()}.xml"
    r = tk.run([nmap, "-sn", "-T4", "-oX", str(xml1), subnet], timeout=300)
    if not xml1.exists():
        rep.add("Devices", "warn", "Device scan failed", (r.stderr or r.stdout or "").strip()[-300:],
                "Run the console as administrator (Windows) or with sudo, and check that Npcap is installed.")
        return []
    hosts = tk.parse_nmap_xml(xml1)["hosts"]
    xml1.unlink(missing_ok=True)
    rep.job.log(f"     {len(hosts)} devices answer on {subnet}")
    ips = [h["ip"] for h in hosts][:64]
    if ips:
        xml2 = out_dir / f"checkup-ports-{os.getpid()}.xml"
        tk.run([nmap, "-Pn", "-T4", "--open", "-p", ",".join(str(p) for p in RISKY_PORTS), "-oX", str(xml2), *ips], timeout=600)
        if xml2.exists():
            ports = {h["ip"]: h["ports"] for h in tk.parse_nmap_xml(xml2)["hosts"]}
            xml2.unlink(missing_ok=True)
            for h in hosts:
                h["ports"] = ports.get(h["ip"], [])
    gw = info.get("gateway")
    for h in hosts:
        for p in h["ports"]:
            sev, name, fix = RISKY_PORTS.get(p["port"], ("info", str(p["port"]), ""))
            if sev == "info" and not (p["port"] in (80, 8291) and h["ip"] == gw):
                continue
            who = f"{h['ip']}" + (f" ({h['hostname'] or h['vendor']})" if (h['hostname'] or h['vendor']) else "")
            rep.add("Devices", sev, f"{name} open on {who}", f"port {p['port']}/{p['proto']} {p['version']}".strip(), fix)
    known = load_baseline()
    if not known:
        count = save_baseline(hosts)
        rep.add("Devices", "info", f"{len(hosts)} devices found and remembered", f"{count} devices saved as the known list",
                "The next check-up warns about devices that were not here today.")
        for h in hosts:
            h["new"] = False
    else:
        new = []
        for h in hosts:
            h["new"] = (h.get("mac") or h["ip"]).lower() not in known
            if h["new"]:
                new.append(h)
        if new:
            names = ", ".join(f"{h['ip']} {h['vendor'] or h['hostname'] or ''}".strip() for h in new[:6])
            rep.add("Devices", "warn", f"{len(new)} new device(s) since the last check-up", names,
                    "If you do not recognise a device, change your Wi-Fi password and check the router's DHCP leases. "
                    "Click 'Accept as known' if they are yours.")
        else:
            rep.add("Devices", "good", f"{len(hosts)} devices, all known", "")
    return hosts


# ------------------------------------------------------------------ MikroTik audit and fixes

def _router():
    from _runtime import setup_import_path
    setup_import_path()
    from netops.mikrotik import RouterOS
    return RouterOS.from_env()


def _yes(value) -> bool:
    return str(value).lower() in ("true", "yes")


def check_mikrotik(rep: Report) -> None:
    rep.job.log("== MikroTik")
    if not os.environ.get("MIKROTIK_HOST"):
        rep.add("MikroTik", "info", "MikroTik audit skipped", "No router set up.", "Add it on the Settings page to audit and fix it.")
        return
    try:
        router = _router()
        res = router.get("system/resource")
    except Exception as exc:                                    # noqa: BLE001
        rep.add("MikroTik", "bad", f"Cannot reach the MikroTik at {os.environ.get('MIKROTIK_HOST')}", str(exc)[:200],
                "Check the address, user, password and that www-ssl (REST API) is enabled.")
        return
    rep.add("MikroTik", "good", f"{res.get('board-name', 'Router')} on RouterOS {res.get('version', '?')}",
            f"uptime {res.get('uptime', '?')}, CPU {res.get('cpu-load', '?')}%")
    scheme = os.environ.get("MIKROTIK_SCHEME", "https")

    def safe(fn):
        try:
            fn()
        except Exception as exc:                                # noqa: BLE001 - one check must not stop the audit
            rep.job.log(f"     (skipped a check: {exc})")

    def services():
        for s in router.get("ip/service") or []:
            name, on = s.get("name"), not _yes(s.get("disabled"))
            if not on:
                continue
            if name in ("telnet", "ftp"):
                rep.add("MikroTik", "bad", f"Service '{name}' is enabled", "It sends passwords in clear text.",
                        "Disable it.", {"id": "mt-service-off", "params": {"name": name}})
            elif name == "api":
                rep.add("MikroTik", "warn", "Plain API (8728) is enabled", "Passwords travel unencrypted.",
                        "Disable it; the console uses the REST API over HTTPS.", {"id": "mt-service-off", "params": {"name": name}})
            elif name == "www" and scheme == "https":
                rep.add("MikroTik", "warn", "WebFig over plain HTTP (www) is enabled", "",
                        "Disable it and use www-ssl (HTTPS).", {"id": "mt-service-off", "params": {"name": name}})
            elif name in ("ssh", "winbox", "www-ssl", "api-ssl") and not s.get("address"):
                rep.add("MikroTik", "info", f"'{name}' accepts connections from any address", f"port {s.get('port')}",
                        f"Limit it to your management network: /ip service set {name} address=10.255.0.0/16")
    safe(services)

    def users():
        for u in router.get("user") or []:
            if u.get("name") == "admin" and not _yes(u.get("disabled")):
                rep.add("MikroTik", "warn", "The default 'admin' user is active", "Attackers try this name first.",
                        "Create your own full-rights user, log in with it, then disable 'admin'.")
    safe(users)

    def upnp():
        u = router.get("ip/upnp") or {}
        if _yes(u.get("enabled")):
            rep.add("MikroTik", "warn", "UPnP is enabled", "Devices on your network can open ports to the internet by themselves.",
                    "Disable UPnP unless a game console really needs it.", {"id": "mt-upnp-off", "params": {}})
    safe(upnp)

    def firewall():
        rules = router.get("ip/firewall/filter") or []
        drop = [r for r in rules if r.get("chain") == "input" and r.get("action") in ("drop", "reject") and not _yes(r.get("disabled"))]
        if not drop:
            rep.add("MikroTik", "bad", "No drop rule in the firewall input chain", "Every service on the router can be reached from the WAN.",
                    "Add the default rules: accept established/related, accept from LAN, drop the rest: "
                    "/ip firewall filter add chain=input in-interface-list=!LAN action=drop comment=\"drop all not coming from LAN\"")
        else:
            rep.add("MikroTik", "good", "The firewall drops unwanted input", f"{len(drop)} drop rule(s) on input")
        dns = router.get("ip/dns") or {}
        if _yes(dns.get("allow-remote-requests")) and not drop:
            rep.add("MikroTik", "bad", "The router answers DNS for the whole internet", "allow-remote-requests=yes without an input drop rule makes it an open resolver.",
                    "Add the input drop rule above (keeps DNS for your LAN).")
    safe(firewall)

    def ssh():
        s = router.get("ip/ssh") or {}
        if "strong-crypto" in s and not _yes(s.get("strong-crypto")):
            rep.add("MikroTik", "warn", "SSH allows weak ciphers", "strong-crypto=no",
                    "Turn on strong-crypto.", {"id": "mt-ssh-strong", "params": {}})
    safe(ssh)

    def exposure():
        lists = {l.get("name") for l in (router.get("interface/list") or [])}
        nd = router.get("ip/neighbor/discovery-settings") or {}
        if nd.get("discover-interface-list") in ("all", "!dynamic", None) and "discover-interface-list" in nd:
            rep.add("MikroTik", "warn", "Neighbour discovery runs on every interface", "It tells the WAN side what router you have.",
                    "Limit it to the LAN list." if "LAN" in lists else "Create an interface list 'LAN' first, then limit it to that list.",
                    {"id": "mt-neighbor-lan", "params": {}} if "LAN" in lists else None)
        mac = router.get("tool/mac-server") or {}
        if mac.get("allowed-interface-list") == "all":
            rep.add("MikroTik", "warn", "MAC Telnet/Winbox is reachable on every interface", "",
                    "Limit it to the LAN list." if "LAN" in lists else "Create an interface list 'LAN' first.",
                    {"id": "mt-macserver-lan", "params": {}} if "LAN" in lists else None)
    safe(exposure)

    def interfaces():
        for i in router.get("interface") or []:
            errs = sum(int(i.get(k) or 0) for k in ("rx-error", "tx-error", "fcs-error"))
            if errs > 100 and i.get("running") in ("true", True):
                rep.add("MikroTik", "warn", f"Interface {i.get('name')} has {errs} errors", "receive/transmit/FCS errors",
                        "Usually a bad cable, a bad connector or a speed/duplex mismatch. Replace the cable first.")
    safe(interfaces)

    def updates():
        router.command("system/package/update/check-for-updates", {})
        u = router.get("system/package/update") or {}
        inst, latest = u.get("installed-version"), u.get("latest-version")
        if inst and latest and inst != latest:
            rep.add("MikroTik", "warn", f"RouterOS {latest} is available (you run {inst})", u.get("channel", ""),
                    "Read the changelog, make a backup, then: /system package update install")
        elif inst:
            rep.add("MikroTik", "good", f"RouterOS {inst} is up to date", u.get("channel", ""))
    safe(updates)


FIXES = {
    "mt-service-off": "Disable a router service",
    "mt-upnp-off": "Disable UPnP",
    "mt-ssh-strong": "Turn on SSH strong-crypto",
    "mt-neighbor-lan": "Limit neighbour discovery to the LAN list",
    "mt-macserver-lan": "Limit MAC Telnet and MAC Winbox to the LAN list",
}
DRY_RUN_VALID = 15 * 60          # an apply must follow a dry run of the same fix within 15 minutes
_dry_runs: dict[str, float] = {}


def fix_plan(action: str, params: dict) -> list[dict]:
    """Each step: the RouterOS command, the REST call that runs it, and where to read the value back."""
    if action == "mt-service-off":
        name = params.get("name")
        if name not in ("telnet", "ftp", "api", "www"):
            raise tk.BadInput("That service cannot be switched off from here.")
        return [{"cli": f"/ip service disable {name}", "method": "PATCH", "path": "ip/service", "by_name": name,
                 "body": {"disabled": "true"}, "read": ("ip/service", name, "disabled")}]
    if action == "mt-upnp-off":
        return [{"cli": "/ip upnp set enabled=no", "method": "POST", "path": "ip/upnp/set", "body": {"enabled": "no"},
                 "read": ("ip/upnp", None, "enabled")}]
    if action == "mt-ssh-strong":
        return [{"cli": "/ip ssh set strong-crypto=yes", "method": "POST", "path": "ip/ssh/set", "body": {"strong-crypto": "yes"},
                 "read": ("ip/ssh", None, "strong-crypto")}]
    if action == "mt-neighbor-lan":
        return [{"cli": "/ip neighbor discovery-settings set discover-interface-list=LAN", "method": "POST",
                 "path": "ip/neighbor/discovery-settings/set", "body": {"discover-interface-list": "LAN"},
                 "read": ("ip/neighbor/discovery-settings", None, "discover-interface-list")}]
    if action == "mt-macserver-lan":
        return [{"cli": "/tool mac-server set allowed-interface-list=LAN", "method": "POST", "path": "tool/mac-server/set",
                 "body": {"allowed-interface-list": "LAN"}, "read": ("tool/mac-server", None, "allowed-interface-list")},
                {"cli": "/tool mac-server mac-winbox set allowed-interface-list=LAN", "method": "POST",
                 "path": "tool/mac-server/mac-winbox/set", "body": {"allowed-interface-list": "LAN"},
                 "read": ("tool/mac-server/mac-winbox", None, "allowed-interface-list")}]
    raise tk.BadInput("Unknown fix.")


def _norm(value) -> str:
    v = str(value).strip().lower()
    return {"yes": "true", "no": "false"}.get(v, v)


def _read(router, step: dict) -> str | None:
    path, name, field = step["read"]
    data = router.get(path, name=name) if name else router.get(path)
    if isinstance(data, list):
        data = data[0] if data else None
    return None if data is None else data.get(field)


def _key(action: str, params: dict) -> str:
    return action + json.dumps(params, sort_keys=True)


def apply_fix(action: str, params: dict, mode: str, confirm: bool, log) -> dict:
    """mode 'preview': the commands only. 'dry-run': read the current values from the router, change nothing.
    'apply': only after a dry run of the same fix, with confirm=True and NETOPS_DRY_RUN=false; reads back after."""
    params = params if isinstance(params, dict) else {}
    plan = fix_plan(action, params)
    target = (lambda st: next(iter(st["body"].values())))
    steps = [{"cli": st["cli"], "rest": f"{st['method']} /rest/{st['path']}" + (f" (item {st['by_name']})" if st.get("by_name") else "")
              + f" {json.dumps(st['body'])}", "target": target(st)} for st in plan]
    dry_setting = os.environ.get("NETOPS_DRY_RUN", "true").lower() != "false"
    out = {"action": action, "title": FIXES[action], "steps": steps, "mode": mode, "dry_run_setting": dry_setting,
           "applied": False, "verified": False}
    if mode == "preview":
        return out
    if mode not in ("dry-run", "apply"):
        raise tk.BadInput("mode must be preview, dry-run or apply")
    router = _router()
    for st, view in zip(plan, steps):
        view["current"] = _read(router, st)
        view["needed"] = _norm(view["current"]) != _norm(view["target"])
    if mode == "dry-run":
        _dry_runs[_key(action, params)] = time.time()
        log.info("fix", f"dry run {action}: " + "; ".join(f"{v['cli']} (now {v['current']})" for v in steps))
        out["message"] = ("Dry run: nothing was changed. " + ("Already done on the router." if not any(v["needed"] for v in steps)
                          else "These values would change."))
        return out
    # apply
    if not confirm:
        raise tk.BadInput("Tick the confirmation box first.")
    ran = _dry_runs.get(_key(action, params))
    if not ran or time.time() - ran > DRY_RUN_VALID:
        raise tk.BadInput("Run the dry run of this fix first (it is valid for 15 minutes).")
    if dry_setting:
        raise tk.BadInput("Dry run is on in Settings (NETOPS_DRY_RUN=true), so the console never changes the router. "
                          "Set it to false on the Settings page to apply fixes.")
    for st, view in zip(plan, steps):
        if not view["needed"]:
            continue
        if st["method"] == "PATCH":
            found = router.get(st["path"], name=st["by_name"]) or []
            if not found:
                raise tk.BadInput(f"{st['by_name']} was not found on the router.")
            router.update(st["path"], found[0][".id"], st["body"])
        else:
            router.command(st["path"], st["body"])
        log.warn("fix", f"applied on the router: {view['cli']}  [{view['rest']}]")
    for st, view in zip(plan, steps):
        view["after"] = _read(router, st)
        view["ok"] = _norm(view["after"]) == _norm(view["target"])
    _dry_runs.pop(_key(action, params), None)
    out["applied"] = True
    out["verified"] = all(v["ok"] for v in steps)
    out["message"] = ("Applied and verified: the router now reports the new values." if out["verified"]
                      else "Applied, but the router does not report the expected value. Check it in Winbox.")
    return out


# ------------------------------------------------------------------ the whole check-up

def run_checkup(job, options: dict, out_dir: Path) -> dict:
    rep = Report(job)
    info = tk.network_info()
    job.log(f"This computer: {info['local_ip'] or '?'}, gateway {info['gateway'] or '?'}, network {info['suggested_subnet'] or '?'}")
    check_connectivity(rep, info)
    wifi = check_wifi(rep) if options.get("wifi", True) else {}
    devices = check_devices(rep, info, out_dir) if options.get("devices", True) else []
    if options.get("mikrotik", True):
        check_mikrotik(rep)
    score = rep.score()
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "E"
    counts = {s: sum(1 for f in rep.findings if f["severity"] == s) for s in ("bad", "warn", "info", "good")}
    job.log(f"== Score {score}/100 ({grade}): {counts['bad']} problems, {counts['warn']} warnings")
    return {"score": score, "grade": grade, "counts": counts, "findings": rep.findings, "network": info,
            "devices": devices, "wifi": wifi, "when": time.time()}
