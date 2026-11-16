#!/usr/bin/env python3
"""Step 4a: ask Oxidized to back up the changed devices right now, and wait
until each backup is done. Oxidized stores every config in Git, so you get a
history of what changed on each device.

Env: OXIDIZED_URL (e.g. http://oxidized.internal:8888), optional
     OXIDIZED_USER / OXIDIZED_PASSWORD (if Oxidized sits behind basic auth),
     PLAN_FILE (default build/plan.json), OXIDIZED_TIMEOUT (seconds, default 300).
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.parse
from pathlib import Path

from httpjson import HttpError, request

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    url = os.environ.get("OXIDIZED_URL", "").rstrip("/")
    if not url:
        print("OXIDIZED_URL is not set: skipping the Oxidized backup.")
        return 0
    headers = {}
    if os.environ.get("OXIDIZED_USER"):
        token = f"{os.environ['OXIDIZED_USER']}:{os.environ.get('OXIDIZED_PASSWORD', '')}"
        headers["Authorization"] = "Basic " + base64.b64encode(token.encode()).decode()
    plan = json.loads(Path(os.environ.get("PLAN_FILE", ROOT / "build/plan.json")).read_text())
    devices = list(plan["devices"])
    if not devices:
        print("No devices changed: nothing to back up.")
        return 0
    timeout = int(os.environ.get("OXIDIZED_TIMEOUT", "300"))

    before, failed = {}, []
    for dev in devices:
        node = urllib.parse.quote(dev)
        try:
            before[dev] = request("GET", f"{url}/node/show/{node}.json", headers).get("last")
            request("GET", f"{url}/node/next/{node}", headers)
            print(f"{dev}: backup requested")
        except HttpError as exc:
            print(f"{dev}: Oxidized does not know this device ({exc}). Is it in router.db?")
            failed.append(dev)

    deadline = time.time() + timeout
    pending = [d for d in devices if d not in failed]
    while pending and time.time() < deadline:
        time.sleep(10)
        for dev in list(pending):
            last = request("GET", f"{url}/node/show/{urllib.parse.quote(dev)}.json", headers).get("last")
            if last and last != before.get(dev):
                status = last.get("status")
                print(f"{dev}: backup finished, status {status}")
                if status != "success":
                    failed.append(dev)
                pending.remove(dev)
    for dev in pending:
        print(f"{dev}: no new backup within {timeout}s")
        failed.append(dev)

    if failed:
        print(f"Backup FAILED for: {', '.join(failed)}")
        return 1
    print("All changed devices are backed up in Oxidized.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
