"""netops-crowdsec: workflow 4. Push CrowdSec's bans to a MikroTik address list.

  netops-crowdsec setup              questions, registers the bouncer with CrowdSec, adds the router rule
  netops-crowdsec check              test CrowdSec and the router
  netops-crowdsec run                keep the router in sync (what the service runs)
  netops-crowdsec sync-once          one full sync, then stop
  netops-crowdsec install-service    run in the background
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys

import _bundle_imports  # noqa: F401  (tells the builder what to include)
from _runtime import VERSION, Asker, fail, install_service, load_config, load_workflow, ok, save_config, step, warn
from _wizard import ask_mikrotik, ask_notifications, ask_safety

SERVICE = "netops-crowdsec"
BOUNCER_NAME = "netops-mikrotik"


def register_bouncer(a: Asker) -> str | None:
    """Ask cscli for a bouncer key, so nobody has to copy it by hand."""
    cscli = shutil.which("cscli")
    if not cscli:
        return None
    if not a.yes("CrowdSec is installed here. Register the bouncer automatically?", True):
        return None
    result = subprocess.run([cscli, "bouncers", "add", BOUNCER_NAME, "-o", "raw"], capture_output=True, text=True)
    if result.returncode != 0 and "already exists" in (result.stderr + result.stdout):
        if a.yes(f"A bouncer named {BOUNCER_NAME} already exists. Replace it with a new key?", True):
            subprocess.run([cscli, "bouncers", "delete", BOUNCER_NAME], capture_output=True)
            result = subprocess.run([cscli, "bouncers", "add", BOUNCER_NAME, "-o", "raw"], capture_output=True, text=True)
    if result.returncode == 0 and result.stdout.strip():
        ok(f"bouncer '{BOUNCER_NAME}' registered")
        return result.stdout.strip().splitlines()[-1]
    warn(f"cscli could not add the bouncer: {result.stderr.strip() or result.stdout.strip()} (run setup as root?)")
    return None


def setup(args) -> int:
    a = Asker(args.yes)
    print("netops-crowdsec setup. Press Enter to keep the value in [brackets].")
    cfg = ask_safety(a)
    step("CrowdSec")
    cfg["CROWDSEC_LAPI_URL"] = a.ask("CROWDSEC_LAPI_URL", "CrowdSec Local API URL", "http://127.0.0.1:8080")
    key = register_bouncer(a)
    cfg["CROWDSEC_BOUNCER_KEY"] = key or a.ask(
        "CROWDSEC_BOUNCER_KEY", f"Bouncer key (on the CrowdSec machine: cscli bouncers add {BOUNCER_NAME})",
        secret=True, required=True)
    cfg["CROWDSEC_INCLUDE_COMMUNITY"] = "true" if a.yes(
        "Also block CrowdSec's community blocklist? (more entries; watch router memory)", False) else "false"
    cfg["CROWDSEC_MAX_ENTRIES"] = a.ask("CROWDSEC_MAX_ENTRIES", "Maximum entries on the router (hEX: about 10000)", "10000")
    cfg["CROWDSEC_ADDRESS_LIST"] = a.ask("CROWDSEC_ADDRESS_LIST", "MikroTik address list", "crowdsec-blocked")
    cfg |= ask_mikrotik(a) | ask_notifications(a)
    path = save_config(cfg)
    ok(f"config saved to {path}")
    load_config()

    from _checks import check_http, check_mikrotik, ensure_raw_drop_rule
    step("Connections")
    lapi = cfg["CROWDSEC_LAPI_URL"].rstrip("/")
    crowdsec = check_http("CrowdSec Local API", "GET", f"{lapi}/v1/decisions/stream?startup=false",
                          {"X-Api-Key": cfg["CROWDSEC_BOUNCER_KEY"]})
    router = check_mikrotik()
    good = bool(crowdsec and router)
    if router and a.yes(f"Add the firewall rule that drops '{cfg['CROWDSEC_ADDRESS_LIST']}' on the router?", True):
        ok(f"drop rule {ensure_raw_drop_rule(router, cfg['CROWDSEC_ADDRESS_LIST'], 'crowdsec: drop banned sources')}")
    if good and a.yes("Do a first sync now?", True):
        sync(once=True)
    step("Background service")
    if not args.no_service and a.yes("Install and start the background service now?", True):
        install_service(SERVICE, ["run"], "netops-crowdsec: sync CrowdSec bans to the MikroTik", a)
    return 0


def check(_args) -> int:
    from _checks import check_http, check_mikrotik
    step("Connections")
    lapi = os.environ.get("CROWDSEC_LAPI_URL", "http://127.0.0.1:8080").rstrip("/")
    crowdsec = check_http("CrowdSec Local API", "GET", f"{lapi}/v1/decisions/stream?startup=false",
                          {"X-Api-Key": os.environ.get("CROWDSEC_BOUNCER_KEY", "")})
    router = check_mikrotik()
    return 0 if crowdsec and router else 1


def sync(once: bool) -> int:
    bouncer = load_workflow("crowdsec_bouncer", "4-security-onion-crowdsec/crowdsec_mikrotik_bouncer.py")
    if "CROWDSEC_BOUNCER_KEY" not in os.environ:
        fail("no bouncer key: run 'netops-crowdsec setup' first")
        return 1
    argv = ["bouncer", "--list", os.environ.get("CROWDSEC_ADDRESS_LIST", "crowdsec-blocked"),
            "--max-entries", os.environ.get("CROWDSEC_MAX_ENTRIES", "10000")]
    if os.environ.get("CROWDSEC_INCLUDE_COMMUNITY") == "true":
        argv.append("--include-community")
    if once:
        argv.append("--once")
    sys.argv = argv
    return bouncer.main()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="netops-crowdsec", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"netops-crowdsec {VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup")
    s.add_argument("--yes", action="store_true")
    s.add_argument("--no-service", action="store_true")
    for name in ("check", "run", "sync-once", "install-service"):
        sub.add_parser(name)
    args = ap.parse_args(argv)
    load_config()
    if args.cmd == "run":
        return sync(once=False)
    if args.cmd == "sync-once":
        return sync(once=True)
    if args.cmd == "install-service":
        ok_ = install_service(SERVICE, ["run"], "netops-crowdsec: sync CrowdSec bans to the MikroTik", Asker(True))
        return 0 if ok_ else 1
    return {"setup": setup, "check": check}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
