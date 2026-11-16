#!/usr/bin/env python3
"""Step 4b: ask LibreNMS whether every changed device is still up.

Waits VERIFY_WAIT seconds first (default 120) so LibreNMS has polled the
devices after the change, then retries until VERIFY_TIMEOUT (default 600).
Open alerts on those devices are printed as warnings.

Env: LIBRENMS_URL (e.g. https://librenms.internal), LIBRENMS_TOKEN,
     PLAN_FILE (default build/plan.json).
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.parse
from pathlib import Path

from httpjson import HttpError, request

ROOT = Path(__file__).resolve().parent.parent


def find_device(api: str, headers: dict, name: str, ip: str):
    for key in (name, ip):
        try:
            found = request("GET", f"{api}/devices/{urllib.parse.quote(key)}", headers)
            if found.get("devices"):
                return found["devices"][0]
        except HttpError as exc:
            if exc.status != 404:
                raise
    return None


def main() -> int:
    url = os.environ.get("LIBRENMS_URL", "").rstrip("/")
    token = os.environ.get("LIBRENMS_TOKEN", "")
    if not url or not token:
        print("LIBRENMS_URL / LIBRENMS_TOKEN not set: skipping the LibreNMS check.")
        return 0
    api, headers = f"{url}/api/v0", {"X-Auth-Token": token}
    plan = json.loads(Path(os.environ.get("PLAN_FILE", ROOT / "build/plan.json")).read_text())
    devices = {name: d["mgmt_ip"] for name, d in plan["devices"].items()}
    if not devices:
        print("No devices changed: nothing to check.")
        return 0

    wait = int(os.environ.get("VERIFY_WAIT", "120"))
    timeout = int(os.environ.get("VERIFY_TIMEOUT", "600"))
    print(f"Waiting {wait}s for LibreNMS to poll the changed devices...")
    time.sleep(wait)

    deadline = time.time() + timeout
    down = dict(devices)
    unknown = []
    while down and time.time() < deadline:
        for name, ip in list(down.items()):
            dev = find_device(api, headers, name, ip)
            if dev is None:
                print(f"{name}: not found in LibreNMS (add it by name or {ip})")
                unknown.append(name)
                down.pop(name)
            elif int(dev.get("status", 0)) == 1:
                print(f"{name}: UP")
                down.pop(name)
                _print_alerts(api, headers, name, dev.get("device_id"))
        if down:
            time.sleep(30)

    for name in down:
        print(f"{name}: DOWN according to LibreNMS")
    if down or unknown:
        print("Check FAILED. Look at the devices above and consider the rollback job.")
        return 1
    print("All changed devices are up in LibreNMS.")
    return 0


def _print_alerts(api: str, headers: dict, name: str, device_id) -> None:
    try:
        alerts = request("GET", f"{api}/alerts?state=1", headers).get("alerts") or []
    except HttpError:
        return
    for alert in alerts:
        if str(alert.get("device_id")) == str(device_id):
            print(f"  WARNING {name}: open alert '{alert.get('name') or alert.get('rule_id')}'")


if __name__ == "__main__":
    sys.exit(main())
