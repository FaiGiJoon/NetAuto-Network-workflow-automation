"""Network tools for the NetAuto console: find the programs (nmap, tshark,
Wireshark, ping, traceroute, the Wi-Fi scanner of the OS), check every input,
build the command lines and turn their output into tables.

Nothing here runs a shell. Commands are argument lists, and every value from
the browser goes through a validator first.
"""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

SYSTEM = platform.system()          # Windows, Linux, Darwin
IS_WINDOWS = SYSTEM == "Windows"
IS_MAC = SYSTEM == "Darwin"

# Where the installers put the programs when they are not on PATH.
_WIN_PF = [os.environ.get("ProgramFiles", r"C:\Program Files"), os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")]
KNOWN_PATHS = {
    "nmap": [str(Path(p) / "Nmap" / "nmap.exe") for p in _WIN_PF] + ["/opt/homebrew/bin/nmap", "/usr/local/bin/nmap"],
    "tshark": [str(Path(p) / "Wireshark" / "tshark.exe") for p in _WIN_PF]
              + ["/Applications/Wireshark.app/Contents/MacOS/tshark", "/opt/homebrew/bin/tshark", "/usr/local/bin/tshark"],
    "dumpcap": [str(Path(p) / "Wireshark" / "dumpcap.exe") for p in _WIN_PF]
               + ["/Applications/Wireshark.app/Contents/MacOS/dumpcap"],
    "wireshark": [str(Path(p) / "Wireshark" / "Wireshark.exe") for p in _WIN_PF]
                 + ["/Applications/Wireshark.app/Contents/MacOS/Wireshark"],
    "docker": [str(Path(p) / "Docker" / "Docker" / "resources" / "bin" / "docker.exe") for p in _WIN_PF],
}

INSTALL_HINTS = {
    "nmap": {"Windows": "winget install Insecure.Nmap  (or nmap.org/download; tick Npcap)",
             "Darwin": "brew install nmap", "Linux": "sudo apt install nmap"},
    "tshark": {"Windows": "winget install WiresharkFoundation.Wireshark, then install Npcap from npcap.com (capture driver)",
               "Darwin": "brew install --cask wireshark", "Linux": "sudo apt install tshark"},
    "wireshark": {"Windows": "winget install WiresharkFoundation.Wireshark",
                  "Darwin": "brew install --cask wireshark", "Linux": "sudo apt install wireshark"},
    "git": {"Windows": "winget install Git.Git", "Darwin": "xcode-select --install", "Linux": "sudo apt install git"},
    "traceroute": {"Windows": "tracert is built in", "Darwin": "built in", "Linux": "sudo apt install traceroute"},
    "ping": {"Windows": "built in", "Darwin": "built in", "Linux": "sudo apt install iputils-ping"},
    "docker": {"Windows": "winget install Docker.DockerDesktop", "Darwin": "brew install --cask docker",
               "Linux": "see docs.docker.com/engine/install"},
    "nmcli": {"Linux": "sudo apt install network-manager"},
}


def hint(tool: str) -> str:
    return INSTALL_HINTS.get(tool, {}).get(SYSTEM, "")


def find_tool(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for candidate in KNOWN_PATHS.get(name, []):
        if candidate and Path(candidate).is_file():
            return candidate
    return None


def traceroute_tool() -> str | None:
    if IS_WINDOWS:
        return find_tool("tracert")
    return find_tool("traceroute") or find_tool("tracepath")


def wifi_tool() -> str | None:
    if IS_WINDOWS:
        return find_tool("netsh")
    if IS_MAC:
        return find_tool("system_profiler")
    return find_tool("nmcli")


def console_encoding(program: str) -> str:
    """Windows' own console tools write in the OEM code page; everything else is UTF-8."""
    if IS_WINDOWS and Path(program).stem.lower() in {"netsh", "ping", "tracert", "route", "ipconfig", "netstat"}:
        return "oem"
    return "utf-8"


def run(cmd: list[str], timeout: int = 20) -> subprocess.CompletedProcess:
    """Run a short command and capture its output (never raises for a non-zero exit)."""
    kwargs = {"creationflags": 0x08000000} if IS_WINDOWS else {}          # CREATE_NO_WINDOW
    return subprocess.run(cmd, capture_output=True, timeout=timeout, text=True,
                          encoding=console_encoding(cmd[0]), errors="replace", **kwargs)


def tool_version(path: str, args: tuple[str, ...] = ("--version",)) -> str:
    try:
        r = run([path, *args], timeout=10)
        text = (r.stdout or r.stderr).strip().splitlines()
        return text[0][:120] if text else ""
    except (OSError, subprocess.SubprocessError):
        return ""


# ------------------------------------------------------------------ validation

class BadInput(ValueError):
    pass


HOSTNAME = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})(?:\.[A-Za-z0-9-]{1,63})*\.?$")
BPF_CHARS = re.compile(r"^[A-Za-z0-9 .:/()!&|<>=\[\]-]{0,200}$")
IFACE_CHARS = re.compile(r"^[A-Za-z0-9 _.:{}\\/()-]{1,200}$")
MAX_SCAN_ADDRESSES = 4096                                               # a /20


def validate_target(value: str, allow_network: bool = True) -> str:
    """An IP address, a network (CIDR) or a host name. Never something that looks like an option."""
    value = (value or "").strip()
    if not value or value.startswith("-") or len(value) > 253:
        raise BadInput("Enter an IP address, a network like 192.168.1.0/24, or a host name.")
    if "/" in value:
        if not allow_network:
            raise BadInput("Enter one address or host name here, not a network.")
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise BadInput(f"'{value}' is not a valid network: {exc}") from None
        if net.num_addresses > MAX_SCAN_ADDRESSES:
            raise BadInput(f"{value} has {net.num_addresses} addresses. Scan /20 or smaller (at most {MAX_SCAN_ADDRESSES}).")
        return str(net)
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if HOSTNAME.match(value):
        return value
    raise BadInput(f"'{value}' is not an IP address, network or host name.")


def validate_bpf(value: str) -> str:
    value = (value or "").strip()
    if value.startswith("-") or not BPF_CHARS.match(value):
        raise BadInput("The capture filter may only use letters, digits, spaces and . : / ( ) ! & | < > = [ ] -")
    return value


def validate_int(value, low: int, high: int, label: str) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise BadInput(f"{label} must be a number.") from None
    if not low <= n <= high:
        raise BadInput(f"{label} must be between {low} and {high}.")
    return n


def validate_interface(value: str, known: list[dict]) -> str:
    """Must be one of the interfaces tshark listed (by number or name)."""
    value = (value or "").strip()
    if not value or value.startswith("-") or not IFACE_CHARS.match(value):
        raise BadInput("Pick a network interface from the list.")
    for item in known:
        if value in (item["index"], item["name"]):
            return item["index"]
    raise BadInput(f"Interface '{value}' is not in the list. Click 'Refresh interfaces'.")


# ------------------------------------------------------------------ local network

def local_ip() -> str | None:
    """The address this computer uses to reach the internet. A UDP connect sends no packets."""
    for probe in ("192.0.2.1", "2001:db8::1"):
        family = socket.AF_INET6 if ":" in probe else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as s:
                s.connect((probe, 9))
                return s.getsockname()[0]
        except OSError:
            continue
    return None


def default_gateway() -> str | None:
    try:
        if IS_WINDOWS:
            out = run(["route", "print", "-4", "0.0.0.0"]).stdout
            m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out, re.M)
        elif IS_MAC:
            out = run(["route", "-n", "get", "default"]).stdout
            m = re.search(r"gateway:\s*(\S+)", out)
        else:
            ip = find_tool("ip")
            if not ip:
                return None
            out = run([ip, "route", "show", "default"]).stdout
            m = re.search(r"default via (\S+)", out)
        return m.group(1) if m else None
    except (OSError, subprocess.SubprocessError):
        return None


def network_info() -> dict:
    ip = local_ip()
    subnet = None
    if ip and ":" not in ip:
        subnet = str(ipaddress.ip_network(f"{ip}/24", strict=False))
    return {"hostname": socket.gethostname(), "local_ip": ip, "gateway": default_gateway(),
            "suggested_subnet": subnet, "system": f"{SYSTEM} {platform.release()}"}


# ------------------------------------------------------------------ ping / traceroute

def ping_cmd(target: str, count: int) -> list[str]:
    ping = find_tool("ping")
    if not ping:
        raise BadInput(f"ping was not found. {hint('ping')}")
    flag = "-n" if IS_WINDOWS else "-c"
    cmd = [ping, flag, str(count)]
    if ":" in target and not IS_WINDOWS and not IS_MAC:
        cmd.append("-6")
    return cmd + [target]


def trace_cmd(target: str, max_hops: int = 20) -> list[str]:
    tool = traceroute_tool()
    if not tool:
        raise BadInput(f"traceroute was not found. {hint('traceroute')}")
    name = Path(tool).stem.lower()
    if name == "tracert":
        return [tool, "-d", "-h", str(max_hops), "-w", "1500", target]
    if name == "tracepath":
        return [tool, "-n", "-m", str(max_hops), target]
    return [tool, "-n", "-m", str(max_hops), "-w", "2", "-q", "2", target]


def _is_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token.strip("()[]"))
        return True
    except ValueError:
        return False


def parse_trace(text: str) -> list[dict]:
    """traceroute -n, tracepath -n and Windows tracert -d: hop number, address, average ms."""
    hops = []
    for line in text.splitlines():
        m = re.match(r"^\s*(\d{1,2})[?:]?\s+(.*)$", line)
        if not m:
            continue
        rest = m.group(2)
        addr = next((t.strip("()[]") for t in rest.split() if _is_ip(t)), None)
        times = [float(t) for t in re.findall(r"<?(\d+(?:\.\d+)?)\s*ms", rest)]
        hops.append({"hop": int(m.group(1)), "address": addr or "*",
                     "ms": round(sum(times) / len(times), 1) if times else None, "timeout": not times})
    return hops


def parse_ping(text: str) -> dict:
    loss = re.search(r"(\d+(?:[.,]\d+)?)\s*%\s*(?:packet\s*)?(?:loss|verlies|verlust|perte|perdidos)", text, re.I) \
        or re.search(r"\((\d+)%", text)
    times = [float(t.replace(",", ".")) for t in re.findall(r"(?:time|tijd|zeit|temps)[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", text, re.I)]
    return {"loss_percent": float(loss.group(1).replace(",", ".")) if loss else None,
            "replies": len(times), "avg_ms": round(sum(times) / len(times), 1) if times else None}


# ------------------------------------------------------------------ nmap

NMAP_PROFILES = {
    "discover": {"label": "Find devices (ping scan)", "args": ["-sn", "-T4"]},
    "quick": {"label": "Quick port scan (top 100)", "args": ["-T4", "-F"]},
    "services": {"label": "Services and versions (top 200)", "args": ["-T4", "-sV", "--top-ports", "200"]},
    "os": {"label": "Operating system guess (admin)", "args": ["-T4", "-O", "--osscan-guess", "-F"]},
}


def nmap_cmd(target: str, profile: str, xml_out: Path) -> list[str]:
    nmap = find_tool("nmap")
    if not nmap:
        raise BadInput(f"nmap was not found. {hint('nmap')}")
    if profile not in NMAP_PROFILES:
        raise BadInput("Unknown scan type.")
    cmd = [nmap, *NMAP_PROFILES[profile]["args"], "--stats-every", "5s", "-oX", str(xml_out)]
    if ":" in target:
        cmd.append("-6")
    return cmd + [target]


def parse_nmap_xml(path: Path) -> dict:
    root = ET.parse(path).getroot()
    hosts = []
    for h in root.findall("host"):
        status = h.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addrs = {a.get("addrtype"): a.get("addr") for a in h.findall("address")}
        vendor = next((a.get("vendor") for a in h.findall("address") if a.get("vendor")), "")
        names = [n.get("name") for n in h.findall("hostnames/hostname")]
        ports = []
        for p in h.findall("ports/port"):
            state = p.find("state")
            svc = p.find("service")
            ports.append({
                "port": int(p.get("portid")), "proto": p.get("protocol"),
                "state": state.get("state") if state is not None else "",
                "service": svc.get("name", "") if svc is not None else "",
                "version": " ".join(x for x in ((svc.get("product", ""), svc.get("version", ""), svc.get("extrainfo", ""))
                                                if svc is not None else ()) if x),
            })
        os_match = h.find("os/osmatch")
        hosts.append({
            "ip": addrs.get("ipv4") or addrs.get("ipv6") or "", "mac": addrs.get("mac", ""), "vendor": vendor,
            "hostname": names[0] if names else "",
            "ports": [p for p in ports if p["state"] == "open"],
            "os": f"{os_match.get('name')} ({os_match.get('accuracy')}%)" if os_match is not None else "",
        })
    run_stats = root.find("runstats/finished")
    return {"hosts": hosts, "summary": run_stats.get("summary", "") if run_stats is not None else ""}


# ------------------------------------------------------------------ Wi-Fi

def wifi_cmd() -> list[str]:
    tool = wifi_tool()
    if not tool:
        raise BadInput("No Wi-Fi scanner found. " + (hint("nmcli") or "This system has no supported Wi-Fi tool."))
    if IS_WINDOWS:
        return [tool, "wlan", "show", "networks", "mode=bssid"]
    if IS_MAC:
        return [tool, "SPAirPortDataType", "-json"]
    return [tool, "-t", "-f", "IN-USE,SSID,BSSID,CHAN,SIGNAL,SECURITY", "dev", "wifi", "list", "--rescan", "auto"]


def band_for(channel: int | None) -> str:
    if channel is None:
        return ""
    return "2.4 GHz" if channel <= 14 else "5 GHz" if channel <= 177 else "6 GHz"


def _int(text) -> int | None:
    m = re.search(r"\d+", str(text or ""))
    return int(m.group()) if m else None


def parse_netsh(text: str) -> list[dict]:
    """netsh wlan show networks mode=bssid, in any language: keys are matched loosely."""
    nets, ssid, auth, enc, cur = [], "", "", "", None
    auth_keys = ("authentication", "verificatie", "authentifizierung", "authentification", "autenticación")
    enc_keys = ("encryption", "versleuteling", "verschlüsselung", "chiffrement", "cifrado")
    chan_keys = ("channel", "kanaal", "kanal", "canal")
    for line in text.splitlines():
        m = re.match(r"^\s*(.+?)\s+:\s?(.*)$", line)
        if not m:
            continue
        key, value = m.group(1).strip(), m.group(2).strip()
        low = key.lower()
        if re.match(r"^ssid\s+\d+$", low):
            ssid, auth, enc, cur = value, "", "", None
        elif re.match(r"^bssid\s+\d+$", low):
            cur = {"ssid": ssid or "(hidden)", "bssid": value.lower(), "signal": None, "channel": None,
                   "band": "", "security": " / ".join(x for x in (auth, enc) if x), "connected": False}
            nets.append(cur)
        elif any(low.startswith(k) for k in auth_keys):
            auth = value
        elif any(low.startswith(k) for k in enc_keys):
            enc = value
        elif cur is not None:
            if value.endswith("%"):
                cur["signal"] = _int(value)
            elif any(low.startswith(k) for k in chan_keys):
                cur["channel"] = _int(value)
            elif low.startswith("band"):
                cur["band"] = value
    for n in nets:
        n["band"] = n["band"] or band_for(n["channel"])
    return nets


def parse_nmcli(text: str) -> list[dict]:
    nets = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = [p.replace("\\:", ":") for p in re.split(r"(?<!\\):", line)]
        if len(parts) < 6:
            continue
        in_use, ssid, bssid, chan, signal, security = parts[:6]
        channel = _int(chan)
        nets.append({"ssid": ssid or "(hidden)", "bssid": bssid.lower(), "signal": _int(signal), "channel": channel,
                     "band": band_for(channel), "security": security or "Open", "connected": in_use.strip() == "*"})
    return nets


def parse_macos(text: str) -> list[dict]:
    data = json.loads(text or "{}")
    nets = []
    for block in data.get("SPAirPortDataType", []):
        for iface in block.get("spairport_airport_interfaces", []):
            current = iface.get("spairport_current_network_information") or {}
            groups = [([current] if current else [], True), (iface.get("spairport_airport_other_local_wireless_networks", []), False)]
            for items, connected in groups:
                for n in items:
                    channel = _int(n.get("spairport_network_channel"))
                    sn = str(n.get("spairport_signal_noise", ""))
                    rssi = _int(sn)
                    signal = max(0, min(100, 2 * (100 - rssi))) if rssi else None   # -50 dBm ~ 100 %, -100 dBm ~ 0 %
                    nets.append({"ssid": n.get("_name", "(hidden)"), "bssid": "", "signal": signal, "channel": channel,
                                 "band": band_for(channel), "security": str(n.get("spairport_security_mode", "")).replace("spairport_security_mode_", "").replace("_", " "),
                                 "connected": connected})
    return nets


def parse_wifi(text: str) -> list[dict]:
    if IS_WINDOWS:
        nets = parse_netsh(text)
    elif IS_MAC:
        nets = parse_macos(text)
    else:
        nets = parse_nmcli(text)
    return sorted(nets, key=lambda n: (-(n["signal"] or 0), n["ssid"]))


def wifi_hint(text: str) -> str:
    """Why a scan found nothing, from the scanner's own message."""
    low = text.lower()
    if "location" in low or "locatie" in low or "standort" in low:
        return ("Windows only shows Wi-Fi networks to apps with Location access. Open Settings > Privacy & security > "
                "Location, turn on 'Location services' and 'Let desktop apps access your location', then scan again.")
    if "no wireless interface" in low or "geen draadloze interface" in low or "wlansvc" in low or "not running" in low:
        return "No Wi-Fi adapter was found, or the WLAN AutoConfig service is not running."
    if IS_MAC:
        return "macOS hides network names from apps without Location access: System Settings > Privacy & Security > Location Services."
    if "not running" in low or "networkmanager" in low:
        return "NetworkManager is not running, so nmcli cannot scan."
    return "No networks found. Is Wi-Fi switched on?"


def connected_ssid_windows() -> str | None:
    tool = wifi_tool()
    if not (IS_WINDOWS and tool):
        return None
    out = run([tool, "wlan", "show", "interfaces"]).stdout
    m = re.search(r"^\s*SSID\s+:\s?(.+)$", out, re.M)
    return m.group(1).strip() if m else None


def wifi_summary(nets: list[dict]) -> dict:
    channels: dict = {}
    for n in nets:
        if n["channel"]:
            channels[n["channel"]] = channels.get(n["channel"], 0) + 1
    weak_security = [n["ssid"] for n in nets if re.search(r"\b(open|wep|none)\b", n["security"] or "open", re.I)]
    return {"networks": len({n["ssid"] for n in nets}), "access_points": len(nets),
            "channels": dict(sorted(channels.items())), "open_or_wep": sorted(set(weak_security))}


# ------------------------------------------------------------------ packet capture (tshark)

def capture_interfaces() -> tuple[list[dict], str]:
    """tshark -D: '1. \\Device\\NPF_{...} (Wi-Fi)' or '1. eth0'. Returns (interfaces, error)."""
    tshark = find_tool("tshark")
    if not tshark:
        return [], f"tshark (Wireshark) was not found. {hint('tshark')}"
    try:
        r = run([tshark, "-D"], timeout=20)
    except (OSError, subprocess.SubprocessError) as exc:
        return [], f"tshark -D failed: {exc}"
    items = []
    for line in r.stdout.splitlines():
        m = re.match(r"^\s*(\d+)\.\s+(\S+)(?:\s+\((.+)\))?\s*$", line)
        if m:
            items.append({"index": m.group(1), "name": m.group(2), "label": m.group(3) or m.group(2)})
    if not items:
        err = (r.stderr or "").strip()
        tip = ("Install Npcap (comes with the Wireshark installer)." if IS_WINDOWS else
               "Run as root, or add yourself to the 'wireshark' group: sudo usermod -aG wireshark $USER, then log in again.")
        return [], f"tshark found no interfaces you may capture on. {tip} {err[:200]}".strip()
    return items, ""


def capture_cmd(iface_index: str, count: int, seconds: int, bpf: str, out_file: Path) -> list[str]:
    tshark = find_tool("tshark")
    if not tshark:
        raise BadInput(f"tshark (Wireshark) was not found. {hint('tshark')}")
    cmd = [tshark, "-i", iface_index, "-c", str(count), "-a", f"duration:{seconds}", "-w", str(out_file), "-P", "-l", "-n"]
    if bpf:
        cmd += ["-f", bpf]
    return cmd


_FIELD_SETS = (
    ["_ws.col.protocol", "_ws.col.info"],         # Wireshark 4.2+
    ["_ws.col.Protocol", "_ws.col.Info"],         # Wireshark 3.x - 4.0
    ["frame.protocols", None],                    # anything: no info column
)


def read_capture(pcap: Path, limit: int = 2000) -> list[dict]:
    """Read a capture back as rows. Tries the column field names of each Wireshark version."""
    tshark = find_tool("tshark")
    if not tshark or not pcap.exists():
        return []
    base = ["frame.number", "frame.time_relative", "ip.src", "ipv6.src", "eth.src", "ip.dst", "ipv6.dst", "eth.dst",
            "frame.len", "tcp.srcport", "udp.srcport", "tcp.dstport", "udp.dstport"]
    for proto_field, info_field in _FIELD_SETS:
        fields = base + [proto_field] + ([info_field] if info_field else [])
        cmd = [tshark, "-r", str(pcap), "-n", "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"]
        for f in fields:
            cmd += ["-e", f]
        try:
            r = run(cmd, timeout=60)
        except (OSError, subprocess.SubprocessError):
            return []
        if r.returncode != 0 and ("valid field" in r.stderr or "aren't valid" in r.stderr or "isn't a valid" in r.stderr):
            continue
        rows = []
        for line in r.stdout.splitlines()[:limit]:
            v = line.split("\t") + [""] * len(fields)
            proto = v[13]
            if proto_field == "frame.protocols":
                proto = proto.split(":")[-1].upper()
            sport = v[9] or v[10]
            dport = v[11] or v[12]
            src = v[2] or v[3] or v[4]
            dst = v[5] or v[6] or v[7]
            rows.append({"no": _int(v[0]) or 0, "time": float(v[1] or 0), "src": src, "dst": dst,
                         "sport": sport, "dport": dport, "proto": proto, "len": _int(v[8]) or 0,
                         "info": v[14] if info_field else ""})
        return rows
    return []


def capture_summary(rows: list[dict]) -> dict:
    protos, talkers, convs = {}, {}, {}
    total = 0
    for r in rows:
        protos[r["proto"]] = protos.get(r["proto"], 0) + 1
        talkers[r["src"]] = talkers.get(r["src"], 0) + r["len"]
        key = " ↔ ".join(sorted((r["src"], r["dst"])))
        convs[key] = convs.get(key, 0) + 1
        total += r["len"]
    top = lambda d, n=8: sorted(d.items(), key=lambda kv: -kv[1])[:n]  # noqa: E731
    return {"packets": len(rows), "bytes": total, "protocols": top(protos, 12),
            "top_talkers": top(talkers), "conversations": top(convs)}


def open_in_wireshark(pcap: Path) -> str:
    ws = find_tool("wireshark")
    if not ws:
        raise BadInput(f"Wireshark was not found. {hint('wireshark')}")
    kwargs = {"creationflags": 0x00000008 | 0x00000200} if IS_WINDOWS else {"start_new_session": True}
    subprocess.Popen([ws, "-r", str(pcap)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs)
    return ws


# ------------------------------------------------------------------ why did it not work?

_ADMIN = ("Start the console from a terminal opened with 'Run as administrator'." if IS_WINDOWS
          else "Run the console with sudo.")
_NPCAP = ("Install Npcap from https://npcap.com (keep 'WinPcap API-compatible mode' ticked), then restart the console."
          if IS_WINDOWS else "")


def explain(kind: str, text: str, returncode: int | None, result: dict | None = None) -> str:
    """Turn a tool's real output into: what went wrong and how to fix it. Empty when it worked."""
    low = (text or "").lower()
    result = result or {}
    if kind == "nmap":
        if "requires root privileges" in low or "requested scan type requires" in low:
            return f"This scan type needs administrator rights. {_ADMIN}"
        if "dnet: failed to open device" in low or "npcap" in low or "winpcap" in low or "pcap_open" in low:
            return f"nmap cannot open the network card. {_NPCAP or _ADMIN}"
        if "failed to resolve" in low:
            return "nmap could not resolve that host name. Check the spelling, or use an IP address."
        if returncode not in (0, None):
            return f"nmap stopped with exit code {returncode}. The output below shows its message."
        if not result.get("hosts"):
            return ("No device answered. Check that the target is your own network (see 'This computer' on the left). "
                    "Windows Firewall blocks ping by default: try 'Quick port scan', which also finds hosts that ignore ping.")
    if kind == "capture":
        if "npcap" in low or "wpcap" in low or "npf driver" in low or "packet.dll" in low:
            return f"Capturing needs Npcap. {_NPCAP}" if IS_WINDOWS else "The capture library (libpcap) does not work: reinstall tshark."
        if "permission" in low or "you don't have permission" in low or "operation not permitted" in low:
            return ("No permission to capture on this card. " + (_ADMIN if IS_WINDOWS else
                    "Run 'sudo usermod -aG wireshark $USER', log out and in again, or start the console with sudo."))
        if "no such device" in low or "doesn't exist" in low or "invalid capture filter" in low:
            return "tshark refused the interface or the filter. Pick another interface, or clear the filter."
        if returncode not in (0, None) and not result.get("rows"):
            return f"tshark stopped with exit code {returncode}. The output below shows its message."
        if not result.get("rows"):
            return ("No packets were captured. Pick the interface you really use (Wi-Fi or Ethernet, not a virtual or "
                    "loopback adapter), make sure there is traffic, or clear the capture filter.")
    if kind == "ping":
        if "could not find host" in low or "unknown host" in low or "name or service not known" in low or "kan host" in low:
            return "The host name could not be resolved: check the spelling, or your DNS (run the Network check-up)."
        if "general failure" in low or "algemene fout" in low:
            return "Windows reports 'General failure': the network adapter is down, or a VPN or firewall blocks it."
        if result.get("loss_percent") == 100.0:
            return ("No replies. The host is down, or it does not answer ping: Windows PCs block ping by default, "
                    "and many routers block it on the WAN side.")
    if kind == "traceroute":
        if "unable to resolve" in low or "kan doelsysteemnaam" in low or "unknown host" in low:
            return "The host name could not be resolved: check the spelling or your DNS."
        hops = result.get("hops") or []
        if hops and all(h.get("timeout") for h in hops):
            return "No router on the way answered. A firewall may block the probes (ICMP), or there is no connection."
    if kind == "wifi" and not result.get("networks"):
        if "ssid" in low and "location" not in low:
            return ("The Wi-Fi scanner answered but its output could not be read. The raw output is below; "
                    "please send it so the parser can learn this format.")
        return wifi_hint(text)
    if kind in ("git-fetch", "git-pull"):
        if "authentication failed" in low or "could not read username" in low or "terminal prompts disabled" in low:
            return ("Git needs you to sign in. Run 'git fetch' once in a terminal in this folder: Git Credential Manager "
                    "opens a browser to log in to GitHub. Then try again here.")
        if "not possible to fast-forward" in low or "diverged" in low:
            return "Your branch and the remote have both changed. Pull from a terminal and choose merge or rebase."
        if "would be overwritten" in low or "commit your changes" in low:
            return "You have local changes that a pull would overwrite. Commit or stash them first."
        if "could not resolve host" in low or "unable to access" in low:
            return "Git cannot reach the remote: check your internet connection, proxy or VPN."
        if returncode not in (0, None):
            return f"git stopped with exit code {returncode}. The output below shows its message."
    return ""
