#!/usr/bin/env python3
"""CrowdSec bouncer for MikroTik: keeps a RouterOS address list in sync with
CrowdSec's ban decisions, so the router drops those IPs.

  1. At start: full sync (adds missing bans, removes bans CrowdSec lifted)
  2. Then every --interval seconds: only the changes

Only touches list entries whose comment starts with "crowdsec", never your own.
Skips allowlisted addresses and very wide ranges, and caps the list size so a
small router (hEX) does not run out of memory.

Register it first on the CrowdSec machine:   cscli bouncers add mikrotik-bouncer
Env: CROWDSEC_LAPI_URL, CROWDSEC_BOUNCER_KEY, MIKROTIK_HOST/USER/PASSWORD

    python crowdsec_mikrotik_bouncer.py                     # local decisions only
    python crowdsec_mikrotik_bouncer.py --include-community # + CrowdSec's community blocklist
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))

from netops import notify  # noqa: E402
from netops.http import HttpError, request  # noqa: E402
from netops.mikrotik import RouterOS  # noqa: E402
from netops.safety import allowlist, dry_run, may_block  # noqa: E402

LOCAL_ORIGINS = {"crowdsec", "cscli", "console"}
_UNITS = {"h": 3600, "m": 60, "s": 1, "ms": 0.001, "us": 1e-6, "µs": 1e-6, "ns": 1e-9}


def go_duration_seconds(text: str) -> int:
    """'3h59m12.5s' -> 14352. Negative or unparsable -> 0 (= already expired)."""
    if not text or text.startswith("-"):
        return 0
    total = 0.0
    for num, unit in re.findall(r"(\d+(?:\.\d+)?)(ms|us|µs|ns|h|m|s)", text):
        total += float(num) * _UNITS[unit]
    return int(total)


def acceptable(decision: dict, include_community: bool) -> tuple[bool, str]:
    if decision.get("type") != "ban":
        return False, f"type {decision.get('type')}"
    if not include_community and decision.get("origin") not in LOCAL_ORIGINS:
        return False, f"origin {decision.get('origin')}"
    value, scope = decision.get("value", ""), (decision.get("scope") or "").lower()
    if scope == "ip":
        return may_block(value)
    if scope == "range":
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return False, f"bad range {value}"
        if net.version == 4 and net.prefixlen < 16:
            return False, f"{value} is too wide to block automatically"
        for allowed in allowlist():
            if allowed.version == net.version and net.overlaps(allowed):
                return False, f"{value} overlaps the allowlist ({allowed})"
        return True, "ok"
    return False, f"scope {decision.get('scope')}"


class Bouncer:
    def __init__(self, router: RouterOS | None, lapi_url: str, key: str, list_name: str,
                 include_community: bool, max_entries: int):
        self.router, self.lapi, self.key = router, lapi_url.rstrip("/"), key
        self.list, self.community, self.max = list_name, include_community, max_entries
        self.active: dict[str, str] = {}      # address -> RouterOS .id (or "dry-run")

    def fetch(self, startup: bool) -> dict:
        return request("GET", f"{self.lapi}/v1/decisions/stream",
                       params={"startup": str(startup).lower()},
                       headers={"X-Api-Key": self.key}) or {}

    def _add(self, d: dict) -> str:
        value, seconds = d["value"], go_duration_seconds(d.get("duration", ""))
        if seconds <= 0:
            return "expired"
        if value in self.active:
            return "exists"
        if len(self.active) >= self.max:
            return "full"
        comment = f"crowdsec: {d.get('scenario', '')}"[:120]
        if dry_run() or self.router is None:
            self.active[value] = "dry-run"
            return "added"
        item = self.router.create("ip/firewall/address-list",
                                  {"list": self.list, "address": value, "timeout": f"{seconds}s", "comment": comment})
        self.active[value] = item.get(".id", "?") if isinstance(item, dict) else "?"
        return "added"

    def _remove(self, value: str) -> bool:
        item_id = self.active.pop(value, None)
        if item_id is None:
            return False
        if not (dry_run() or self.router is None) and item_id not in ("?", "dry-run"):
            try:
                self.router.delete("ip/firewall/address-list", item_id)
            except HttpError as exc:
                if exc.status != 404:      # already expired on the router is fine
                    raise
        return True

    def load_existing(self) -> None:
        """Pick up entries a previous run created, so a restart does not duplicate them."""
        if dry_run() or self.router is None:
            return
        for item in self.router.list_addresses(self.list):
            if str(item.get("comment", "")).startswith("crowdsec"):
                self.active[item["address"]] = item[".id"]

    def apply(self, stream: dict, full: bool) -> dict:
        added = removed = skipped = capped = 0
        wanted = {}
        for d in stream.get("new") or []:
            ok, why = acceptable(d, self.community)
            if ok:
                wanted[d["value"]] = d
            else:
                skipped += 1
        if full:
            for value in [v for v in self.active if v not in wanted]:
                removed += self._remove(value)
        for d in stream.get("deleted") or []:
            removed += self._remove(d.get("value", ""))
        for d in wanted.values():
            outcome = self._add(d)
            added += outcome == "added"
            capped += outcome == "full"
        return {"added": added, "removed": removed, "skipped": skipped, "active": len(self.active),
                "capped": capped}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--list", default="crowdsec-blocked")
    ap.add_argument("--interval", type=int, default=30)
    ap.add_argument("--include-community", action="store_true")
    ap.add_argument("--max-entries", type=int, default=10000)
    ap.add_argument("--once", action="store_true", help="one full sync, then stop")
    a = ap.parse_args()

    router = None if dry_run() else RouterOS.from_env()
    b = Bouncer(router, os.environ.get("CROWDSEC_LAPI_URL", "http://127.0.0.1:8080"),
                os.environ["CROWDSEC_BOUNCER_KEY"], a.list, a.include_community, a.max_entries)
    b.load_existing()
    first = True
    while True:
        try:
            result = b.apply(b.fetch(startup=first), full=first)
            if first or result["added"] or result["removed"]:
                print(f"sync: {result}")
            if result["capped"]:
                notify.send(f"netops: CrowdSec list on the router is full ({a.max_entries}), some bans skipped")
            first = False
        except (HttpError, OSError) as exc:
            print(f"sync failed, retrying: {exc}")
        if a.once:
            return 0
        time.sleep(a.interval)


if __name__ == "__main__":
    sys.exit(main())
