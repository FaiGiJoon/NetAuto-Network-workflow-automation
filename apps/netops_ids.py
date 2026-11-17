"""netops-ids: workflow 1. Block attackers seen by Snort/Suricata on a MikroTik,
and power-cycle PoE devices that Zabbix reports as down.

  netops-ids setup                 answer a few questions, everything else is done for you
  netops-ids check                 test the config and the connection to the router
  netops-ids run                   watch the alert file (what the service runs)
  netops-ids poe-restart --device cam-12 --switch 10.255.10.1 --port ether8
  netops-ids install-service       run in the background, start at boot
  netops-ids install-suricata      install Suricata (OISF) with rules, daily updates and the mirror port
  netops-ids zabbix-setup          create the PoE-restart script, action and hosts in Zabbix
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import _bundle_imports  # noqa: F401  (tells the builder what to include)
from _runtime import VERSION, Asker, install_service, load_config, ok, save_config, step, warn
from _wizard import ask_mikrotik, ask_notifications, ask_safety, ask_tickets

SERVICE = "netops-ids"
ALERT_FILES = ["/var/log/suricata/eve.json", "/var/log/snort/alert_json.txt"]


def setup(args) -> int:
    a = Asker(args.yes)
    print("netops-ids setup. Press Enter to keep the value in [brackets].")
    cfg = ask_safety(a) | ask_mikrotik(a)
    step("IDS alerts")
    found = next((f for f in ALERT_FILES if Path(f).exists()), ALERT_FILES[0])
    cfg["IDS_ALERT_FILE"] = a.ask("IDS_ALERT_FILE", "Alert file (Suricata eve.json or Snort alert_json)", found)
    cfg["IDS_THRESHOLD"] = a.ask("IDS_THRESHOLD", "Alerts from one IP before it is blocked", "5")
    cfg["IDS_WINDOW"] = a.ask("IDS_WINDOW", "...within this many seconds", "60")
    cfg["IDS_BLOCK_TIMEOUT"] = a.ask("IDS_BLOCK_TIMEOUT", "How long a block lasts (1h, 1d, 7d)", "1d")
    cfg["IDS_ADDRESS_LIST"] = a.ask("IDS_ADDRESS_LIST", "MikroTik address list", "netops-blocked")
    cfg |= ask_notifications(a) | ask_tickets(a)
    path = save_config(cfg)
    ok(f"config saved to {path}")
    load_config()

    from _checks import check_mikrotik, ensure_raw_drop_rule
    step("Checking the router")
    router = check_mikrotik()
    if router and a.yes(f"Add the firewall rule that drops '{cfg['IDS_ADDRESS_LIST']}' on the router (raw table)?", True):
        result = ensure_raw_drop_rule(router, cfg["IDS_ADDRESS_LIST"], "netops: drop blocked sources")
        ok(f"drop rule {result}")
    if not Path(cfg["IDS_ALERT_FILE"]).exists():
        warn(f"{cfg['IDS_ALERT_FILE']} does not exist yet.")
        if not args.no_service and a.yes("Install and configure Suricata on this machine now (Ubuntu/Debian)?", True):
            import _suricata
            save_config(_suricata.install(a))
    if not args.no_service and a.yes("Set up Zabbix (PoE restart script, action and hosts) through its API now?", False):
        import _zabbix
        save_config(_zabbix.setup(a, "/opt/netops/netops-ids"))
    step("Background service")
    if not args.no_service and a.yes("Install and start the background service now?", True):
        install_service(SERVICE, ["run"], "netops-ids: block attackers seen by the IDS", a)
    print("\nDone. Zabbix remote command for dead PoE devices:")
    print(f"   {' '.join(_self())} poe-restart --device {{HOST.NAME}} --switch {{$POE_SWITCH}} --port {{$POE_PORT}}")
    return 0


def _self():
    from _runtime import self_command
    return self_command()


def check(_args) -> int:
    from _checks import check_mikrotik, check_notifications, check_tickets
    import os
    step("Config")
    ok(f"dry run: {os.environ.get('NETOPS_DRY_RUN', 'false')}")
    alert_file = os.environ.get("IDS_ALERT_FILE", ALERT_FILES[0])
    (ok if Path(alert_file).exists() else warn)(f"alert file {alert_file}")
    step("Connections")
    router = check_mikrotik()
    check_notifications()
    check_tickets()
    return 0 if router else 1


def run(args) -> int:
    import os
    watcher_argv = ["alert_watcher", "--file", args.file or os.environ.get("IDS_ALERT_FILE", ALERT_FILES[0]),
                    "--threshold", os.environ.get("IDS_THRESHOLD", "5"),
                    "--window", os.environ.get("IDS_WINDOW", "60"),
                    "--timeout", os.environ.get("IDS_BLOCK_TIMEOUT", "1d"),
                    "--list", os.environ.get("IDS_ADDRESS_LIST", "netops-blocked")]
    if args.from_start:
        watcher_argv.append("--from-start")
    if args.once:
        watcher_argv.append("--once")
    from _runtime import load_workflow
    watcher = load_workflow("alert_watcher", "1-ids-zabbix-autoremediate/alert_watcher.py")
    sys.argv = watcher_argv
    return watcher.main()


def poe_restart(args) -> int:
    from _runtime import setup_import_path
    setup_import_path()
    from netops.actions import poe_restart as restart
    result = restart(args.device, args.switch, args.port, args.duration, args.max_per_day)
    print(result)
    return 0 if result in ("restarted", "dry-run", "limit") else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="netops-ids", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"netops-ids {VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup", help="guided setup")
    s.add_argument("--yes", action="store_true", help="no questions: use the current config and environment")
    s.add_argument("--no-service", action="store_true", help="do not install the background service")
    sub.add_parser("check", help="test config and connections")
    r = sub.add_parser("run", help="watch the alert file")
    r.add_argument("--file")
    r.add_argument("--from-start", action="store_true")
    r.add_argument("--once", action="store_true")
    p = sub.add_parser("poe-restart", help="power-cycle a PoE port (for Zabbix)")
    p.add_argument("--device", required=True)
    p.add_argument("--switch", required=True)
    p.add_argument("--port", required=True)
    p.add_argument("--duration", default="5s")
    p.add_argument("--max-per-day", type=int, default=3)
    sub.add_parser("install-service", help="run in the background")
    i = sub.add_parser("install-suricata", help="install and configure Suricata (Ubuntu/Debian, root)")
    i.add_argument("--yes", action="store_true")
    z = sub.add_parser("zabbix-setup", help="create the PoE-restart script, action and hosts in Zabbix")
    z.add_argument("--yes", action="store_true")
    z.add_argument("--netops-path", default="/opt/netops/netops-ids",
                   help="path to netops-ids as the Zabbix server sees it")
    args = ap.parse_args(argv)
    load_config()
    if args.cmd == "install-suricata":
        import _suricata
        save_config(_suricata.install(Asker(args.yes)))
        return 0
    if args.cmd == "zabbix-setup":
        import _zabbix
        save_config(_zabbix.setup(Asker(args.yes), args.netops_path))
        return 0
    if args.cmd == "install-service":
        return 0 if install_service(SERVICE, ["run"], "netops-ids: block attackers seen by the IDS", Asker(True)) else 1
    return {"setup": setup, "check": check, "run": run, "poe-restart": poe_restart}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
