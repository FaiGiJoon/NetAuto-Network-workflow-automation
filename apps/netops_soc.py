"""netops-soc: workflow 2. The SOAR step for Wazuh: check an attacker's
reputation, block it on OPNsense, open an alert in TheHive, notify.

  netops-soc setup            questions + installs itself into Wazuh (on the Wazuh manager, as root)
  netops-soc check            test AbuseIPDB, OPNsense and TheHive
  netops-soc test             run a sample alert in dry-run mode
  netops-soc handle <file>    handle one Wazuh alert (what Wazuh runs)
  netops-soc install-wazuh    only the Wazuh part of setup
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import _bundle_imports  # noqa: F401  (tells the builder what to include)
from _runtime import (VERSION, Asker, IS_WINDOWS, fail, load_config, load_workflow, ok, save_config,
                      self_command, step, warn, workflow_path)
from _wizard import ask_notifications, ask_safety

OSSEC = Path("/var/ossec")
INTEGRATION_NAME = "custom-netops-soar"
INTEGRATION_BLOCK = """  <integration>
    <name>custom-netops-soar</name>
    <level>10</level>
    <alert_format>json</alert_format>
  </integration>"""
RULES_MARKER = 'rule id="100200"'
SAMPLE_ALERT = {"id": "sample.1", "rule": {"id": "100200", "level": 12, "description": "Suricata high severity: ET EXPLOIT sample"},
                "agent": {"name": "sensor-01"}, "data": {"src_ip": "203.0.113.7", "alert": {"signature": "ET EXPLOIT sample"}}}


def soar():
    return load_workflow("soar", "2-soc-wazuh-thehive/custom-netops-soar.py")


def setup(args) -> int:
    a = Asker(args.yes)
    print("netops-soc setup. Press Enter to keep the value in [brackets].")
    cfg = ask_safety(a)
    step("Reputation check (AbuseIPDB, free key at abuseipdb.com). Without a key nothing is blocked automatically.")
    cfg["ABUSEIPDB_KEY"] = a.ask("ABUSEIPDB_KEY", "AbuseIPDB API key", secret=True)
    cfg["ABUSE_THRESHOLD"] = a.ask("ABUSE_THRESHOLD", "Block from this abuse score (0-100)", "75")
    step("OPNsense (System > Access > Users > API keys). Press Enter to skip blocking.")
    cfg["OPNSENSE_URL"] = a.ask("OPNSENSE_URL", "OPNsense URL, e.g. https://10.255.0.1")
    if cfg["OPNSENSE_URL"]:
        cfg["OPNSENSE_KEY"] = a.ask("OPNSENSE_KEY", "API key", required=True)
        cfg["OPNSENSE_SECRET"] = a.ask("OPNSENSE_SECRET", "API secret", secret=True, required=True)
        cfg["OPNSENSE_ALIAS"] = a.ask("OPNSENSE_ALIAS", "Alias that a block rule uses", "netops_blocked")
        cfg["OPNSENSE_VERIFY_TLS"] = "true" if a.yes("Check OPNsense's TLS certificate?", True) else "false"
    step("TheHive (press Enter to skip)")
    cfg["THEHIVE_URL"] = a.ask("THEHIVE_URL", "TheHive URL, e.g. http://thehive:9000")
    if cfg["THEHIVE_URL"]:
        cfg["THEHIVE_KEY"] = a.ask("THEHIVE_KEY", "TheHive API key", secret=True, required=True)
    cfg |= ask_notifications(a)
    path = save_config(cfg)
    ok(f"config saved to {path}")
    load_config()
    check(args)
    if args.no_service:
        pass
    elif OSSEC.exists():
        if a.yes("Wazuh found on this machine. Install the integration into Wazuh now?", True):
            install_wazuh(a)
    else:
        warn("Wazuh is not installed here. Run 'netops-soc setup' again on the Wazuh manager.")
    return 0


def check(_args) -> int:
    from _checks import basic_auth, check_http
    good = True
    step("Connections")
    if os.environ.get("ABUSEIPDB_KEY"):
        base = os.environ.get("ABUSEIPDB_URL", "https://api.abuseipdb.com")
        good &= check_http("AbuseIPDB", "GET", f"{base}/api/v2/check?ipAddress=127.0.0.1",
                           {"Key": os.environ["ABUSEIPDB_KEY"]})
    else:
        warn("no AbuseIPDB key: alerts go to TheHive for review, nothing is blocked")
    if os.environ.get("OPNSENSE_URL"):
        alias = os.environ.get("OPNSENSE_ALIAS", "netops_blocked")
        good &= check_http(f"OPNsense alias {alias}", "GET",
                           f"{os.environ['OPNSENSE_URL'].rstrip('/')}/api/firewall/alias_util/list/{alias}",
                           {"Authorization": basic_auth(os.environ.get("OPNSENSE_KEY", ""), os.environ.get("OPNSENSE_SECRET", ""))},
                           os.environ.get("OPNSENSE_VERIFY_TLS", "true") != "false")
    if os.environ.get("THEHIVE_URL"):
        good &= check_http("TheHive", "GET", f"{os.environ['THEHIVE_URL'].rstrip('/')}/api/v1/user/current",
                           {"Authorization": f"Bearer {os.environ.get('THEHIVE_KEY', '')}"})
    return 0 if good else 1


def _insert_once(path: Path, marker: str, block: str, before: str | None) -> str:
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    if marker in text:
        return "already there"
    if path.exists():
        shutil.copy2(path, path.with_suffix(path.suffix + ".netops-backup"))
    if before and before in text:
        idx = text.rindex(before)
        text = text[:idx] + block + "\n" + text[idx:]
    else:
        text = text + ("\n" if text and not text.endswith("\n") else "") + block + "\n"
    path.write_text(text, encoding="utf-8")
    return "added"


def install_wazuh(a: Asker) -> int:
    if IS_WINDOWS or os.geteuid() != 0:
        fail("Installing into Wazuh needs Linux and root: sudo netops-soc install-wazuh")
        return 1
    step("Installing into Wazuh")
    cmd = self_command()
    if getattr(sys, "frozen", False):                       # copy the executable to a fixed place
        dest = Path("/opt/netops/bin/netops-soc")
        dest.parent.mkdir(parents=True, exist_ok=True)
        if Path(sys.executable).resolve() != dest:
            shutil.copy2(sys.executable, dest)
        cmd = [str(dest)]
    state = Path("/var/lib/netops/wazuh")
    state.mkdir(parents=True, exist_ok=True)
    shutil.chown(state, "wazuh", "wazuh")
    config = Path(os.environ.get("NETOPS_CONFIG", "/etc/netops/env"))
    shutil.chown(config, "root", "wazuh")
    os.chmod(config, 0o640)
    wrapper = OSSEC / "integrations" / INTEGRATION_NAME
    wrapper.write_text("#!/bin/sh\n# Installed by netops-soc. Wazuh calls this with: <alert_file> <api_key> <hook_url>\n"
                       f"export NETOPS_CONFIG={config} NETOPS_STATE_DIR={state}\n"
                       f"exec {' '.join(cmd)} handle \"$1\"\n")
    os.chmod(wrapper, 0o750)
    shutil.chown(wrapper, "root", "wazuh")
    ok(f"integration script {wrapper}")

    result = _insert_once(OSSEC / "etc/ossec.conf", INTEGRATION_NAME, INTEGRATION_BLOCK, "</ossec_config>")
    ok(f"ossec.conf integration: {result}")
    rules = workflow_path("2-soc-wazuh-thehive/local_rules.xml").read_text()
    result = _insert_once(OSSEC / "etc/rules/local_rules.xml", RULES_MARKER, rules, None)
    ok(f"local_rules.xml: {result}")
    if a.yes("Restart wazuh-manager now to load it?", True):
        subprocess.run(["systemctl", "restart", "wazuh-manager"], check=False)
        ok("wazuh-manager restarted")
    print("\nOn each sensor with Suricata/Zeek, add the <localfile> blocks from ossec-integration.xml to the agent's ossec.conf.")
    return 0


def handle(args) -> int:
    alert = json.loads(Path(args.alert_file).read_text(encoding="utf-8"))
    print(json.dumps(soar().handle(alert)))
    return 0


def test(_args) -> int:
    os.environ["NETOPS_DRY_RUN"] = "true"
    with tempfile.TemporaryDirectory() as d:
        os.environ["NETOPS_STATE_DIR"] = d
        print("Sample alert from 203.0.113.7 (dry run, nothing is blocked):")
        print(json.dumps(soar().handle(SAMPLE_ALERT), indent=2))
    return 0


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    commands = {"setup", "check", "test", "handle", "install-wazuh", "-h", "--help", "--version"}
    if argv and argv[0] not in commands and Path(argv[0]).is_file():
        argv = ["handle", argv[0]]                     # called directly by Wazuh
    ap = argparse.ArgumentParser(prog="netops-soc", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"netops-soc {VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup")
    s.add_argument("--yes", action="store_true")
    s.add_argument("--no-service", action="store_true", help="do not install into Wazuh")
    sub.add_parser("check")
    sub.add_parser("test")
    h = sub.add_parser("handle")
    h.add_argument("alert_file")
    h.add_argument("rest", nargs="*")
    w = sub.add_parser("install-wazuh")
    w.add_argument("--yes", action="store_true")
    args = ap.parse_args(argv)
    load_config()
    if args.cmd == "install-wazuh":
        return install_wazuh(Asker(args.yes))
    return {"setup": setup, "check": check, "test": test, "handle": handle}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
