"""Install and configure Suricata (OISF) for workflow 1 on Ubuntu or Debian.

Uses the OISF tools: the suricata package (OISF PPA on Ubuntu), suricata-update
for the rules, and the free rule sources listed in suricata-intel-index.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from pathlib import Path

from _runtime import Asker, fail, ok, step, warn

CONFIG = Path("/etc/suricata/suricata.yaml")
DEFAULTS = Path("/etc/default/suricata")
CRON = Path("/etc/cron.d/suricata-update")
EVE = "/var/log/suricata/eve.json"
# Free extra sources from suricata-intel-index. Each one is only enabled if
# 'suricata-update list-sources' still offers it.
EXTRA_SOURCES = {
    "oisf/trafficid": "recognise apps and services (YouTube, Netflix, games)",
    "sslbl/ssl-fp-blacklist": "TLS certificates of known malware (abuse.ch)",
    "sslbl/ja3-fingerprints": "TLS fingerprints of known malware (abuse.ch)",
    "tgreen/hunting": "extra 'hunting' rules, noisier but good for learning",
}


# ---------------------------------------------------------- config edits

def set_home_net(text: str, networks: list[str]) -> str:
    value = "[" + ",".join(networks) + "]"
    new, count = re.subn(r'(?m)^(\s*HOME_NET:\s*)"[^"]*"', rf'\g<1>"{value}"', text, count=1)
    if not count:
        raise ValueError("HOME_NET not found in suricata.yaml")
    return new


def set_af_packet_interface(text: str, iface: str) -> str:
    """Change the first '- interface:' under 'af-packet:'."""
    m = re.search(r"(?m)^af-packet:\s*$", text)
    if not m:
        raise ValueError("af-packet section not found in suricata.yaml")
    rest = text[m.end():]
    new_rest, count = re.subn(r"(?m)^(\s*-\s*interface:\s*)\S+", rf"\g<1>{iface}", rest, count=1)
    if not count:
        raise ValueError("no '- interface:' under af-packet in suricata.yaml")
    return text[:m.end()] + new_rest


def set_defaults_iface(text: str, iface: str) -> str:
    """Debian/Ubuntu /etc/default/suricata: IFACE=..."""
    if re.search(r"(?m)^IFACE=", text):
        return re.sub(r"(?m)^IFACE=.*$", f"IFACE={iface}", text)
    return text + f"\nIFACE={iface}\n"


# ------------------------------------------------------------- discovery

def interfaces() -> list[dict]:
    """[{name, ipv4: [cidr...]}] for real network interfaces."""
    out = []
    for path in sorted(Path("/sys/class/net").iterdir()) if Path("/sys/class/net").exists() else []:
        name = path.name
        if name == "lo" or name.startswith(("docker", "br-", "veth", "virbr", "tailscale", "wg")):
            continue
        out.append({"name": name, "ipv4": []})
    try:
        lines = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True).stdout
    except FileNotFoundError:
        lines = ""
    for line in lines.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            for iface in out:
                if iface["name"] == parts[1]:
                    iface["ipv4"].append(parts[3])
    return out


def suggest_home_net(ifaces: list[dict]) -> list[str]:
    nets = []
    for iface in ifaces:
        for cidr in iface["ipv4"]:
            net = ipaddress.ip_interface(cidr).network
            if net.is_private and str(net) not in nets:
                nets.append(str(net))
    return nets or ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]


def os_id() -> str:
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if line.startswith("ID="):
                return line.split("=", 1)[1].strip('"')
    except FileNotFoundError:
        pass
    return "unknown"


# --------------------------------------------------------------- install

def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    print("   $ " + " ".join(cmd))
    return subprocess.run(cmd, check=check, text=True)


def install(a: Asker) -> dict:
    """Returns config updates (IDS_ALERT_FILE). Raises SystemExit on a hard stop."""
    import os
    if os.name == "nt" or not shutil.which("apt-get"):
        raise SystemExit("install-suricata works on Ubuntu or Debian. Install Suricata yourself on other systems.")
    if os.geteuid() != 0:
        raise SystemExit("Run it as root: sudo netops-ids install-suricata")

    step("Network interfaces")
    ifaces = interfaces()
    for i in ifaces:
        print(f"   {i['name']:<16} {', '.join(i['ipv4']) or '(no IP: good for the mirror port)'}")
    no_ip = next((i["name"] for i in ifaces if not i["ipv4"]), ifaces[0]["name"] if ifaces else "eth0")
    iface = a.ask("SURICATA_INTERFACE", "Interface that receives the mirrored traffic", no_ip, required=True)
    if any(i["name"] == iface and i["ipv4"] for i in ifaces):
        warn(f"{iface} has an IP address. That works, but a separate port without IP is better.")
    home = a.ask("SURICATA_HOME_NET", "Your own networks (HOME_NET, comma-separated)",
                 ",".join(suggest_home_net(ifaces)), required=True)
    networks = [n.strip() for n in home.split(",") if n.strip()]
    for n in networks:
        ipaddress.ip_network(n, strict=False)

    step("Installing Suricata")
    distro = os_id()
    _run(["apt-get", "update", "-qq"])
    if distro == "ubuntu":
        _run(["apt-get", "install", "-y", "-qq", "software-properties-common"])
        _run(["add-apt-repository", "-y", "ppa:oisf/suricata-stable"])
        _run(["apt-get", "update", "-qq"])
    _run(["apt-get", "install", "-y", "-qq", "suricata", "jq"])
    ok("suricata installed" + (" from the OISF PPA" if distro == "ubuntu" else ""))

    step("Configuring")
    shutil.copy2(CONFIG, CONFIG.with_suffix(".yaml.netops-backup"))
    text = set_af_packet_interface(set_home_net(CONFIG.read_text(), networks), iface)
    CONFIG.write_text(text)
    ok(f"suricata.yaml: HOME_NET={networks}, af-packet interface {iface} (backup: suricata.yaml.netops-backup)")
    if DEFAULTS.exists():
        DEFAULTS.write_text(set_defaults_iface(DEFAULTS.read_text(), iface))
        ok(f"{DEFAULTS}: IFACE={iface}")

    step("Rules (suricata-update)")
    available = subprocess.run(["suricata-update", "list-sources", "--free"], capture_output=True, text=True).stdout
    for name, why in EXTRA_SOURCES.items():
        if name in available and a.yes(f"Also use {name}? ({why})", name != "tgreen/hunting"):
            _run(["suricata-update", "enable-source", name], check=False)
    _run(["suricata-update"])
    CRON.write_text("# Installed by netops-ids: new rules every night, then reload without a restart.\n"
                    "17 4 * * * root suricata-update -q && systemctl reload suricata\n")
    ok(f"daily rule update at 04:17 ({CRON})")

    step("Starting")
    test = subprocess.run(["suricata", "-T", "-c", str(CONFIG)], capture_output=True, text=True)
    if test.returncode != 0:
        fail("Suricata does not accept the config:\n" + (test.stderr or test.stdout)[-1500:])
        raise SystemExit(1)
    _run(["systemctl", "enable", "suricata"])
    _run(["systemctl", "restart", "suricata"])
    ok("suricata running")
    print(f"""
Test it: on a device whose traffic is mirrored, run
    curl http://testmynids.org/uid/index.html
then here:
    sudo tail -f {EVE} | jq 'select(.event_type=="alert") | .alert.signature'
You should see 'GPL ATTACK_RESPONSE id check returned root'.""")
    return {"IDS_ALERT_FILE": EVE, "SURICATA_INTERFACE": iface, "SURICATA_HOME_NET": ",".join(networks)}
