#!/usr/bin/env python3
"""Zabbix remote command: power-cycle the PoE port of a device that went down.

Zabbix runs this when a "device unreachable" trigger fires. It restarts the
port at most --max-per-day times per device. After that it stops and opens
a ticket, because a device that keeps dying needs a person, not a reboot.

    zabbix_poe_restart.py --device cam-utr-12 --switch 10.255.10.1 --port ether7
    (in Zabbix: --device {HOST.NAME} --switch {$POE_SWITCH} --port {$POE_PORT})
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))

from netops.actions import poe_restart  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--device", required=True)
    ap.add_argument("--switch", required=True, help="IP or name of the MikroTik switch")
    ap.add_argument("--port", required=True, help="PoE port, e.g. ether7")
    ap.add_argument("--duration", default="5s")
    ap.add_argument("--max-per-day", type=int, default=3)
    a = ap.parse_args()
    result = poe_restart(a.device, a.switch, a.port, a.duration, a.max_per_day)
    return 0 if result in ("restarted", "dry-run", "limit") else 1


if __name__ == "__main__":
    sys.exit(main())
