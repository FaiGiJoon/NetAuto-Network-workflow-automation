#!/usr/bin/env python3
"""Watch Snort 3 or Suricata alerts and block attackers on a MikroTik.

Reads the alert file line by line (JSON). When one source IP triggers
--threshold alerts within --window seconds, or one alert of the highest
severity, the IP is:
  1. checked against the allowlist (your own networks are never blocked)
  2. added to a MikroTik address list with a timeout (a firewall rule drops it)
  3. written up in a ticket, and announced in Teams/Slack/Telegram

    python alert_watcher.py --file /var/log/suricata/eve.json
    python alert_watcher.py --file /var/log/snort/alert_json.txt --threshold 10
    NETOPS_DRY_RUN=true python alert_watcher.py --file sample.json --from-start --once
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import defaultdict, deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))

from netops import notify, ticket  # noqa: E402
from netops.http import HttpError  # noqa: E402
from netops.mikrotik import RouterOS  # noqa: E402
from netops.safety import RateLimiter, dry_run, may_block  # noqa: E402


def parse_event(line: str) -> dict | None:
    """Normalise a Suricata eve.json or Snort 3 alert_json line."""
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(e, dict):
        return None
    if e.get("event_type") == "alert" and "alert" in e:          # Suricata
        return {"src": e.get("src_ip"), "dst": e.get("dest_ip"),
                "sig": e["alert"].get("signature", "?"), "severity": int(e["alert"].get("severity", 3))}
    if "src_addr" in e and ("msg" in e or "rule" in e):            # Snort 3
        return {"src": e.get("src_addr"), "dst": e.get("dst_addr"),
                "sig": e.get("msg", e.get("rule", "?")), "severity": int(e.get("priority", 3))}
    return None


class Detector:
    """Sliding window per source IP. Fires once per IP per window."""

    def __init__(self, threshold: int, window: int, instant_severity: int = 1):
        self.threshold, self.window, self.instant = threshold, window, instant_severity
        self.seen: dict[str, deque] = defaultdict(deque)
        self.fired: dict[str, float] = {}

    def feed(self, event: dict, now: float) -> bool:
        src = event.get("src")
        if not src:
            return False
        if src in self.fired and now - self.fired[src] < self.window:
            return False
        q = self.seen[src]
        q.append((now, event["sig"]))
        while q and now - q[0][0] > self.window:
            q.popleft()
        if len(q) >= self.threshold or event["severity"] <= self.instant:
            self.fired[src] = now
            return True
        return False

    def signatures(self, src: str) -> list[str]:
        return sorted({sig for _, sig in self.seen[src]})


def respond(ip: str, sigs: list[str], args, router: RouterOS | None) -> str:
    ok, why = may_block(ip)
    if not ok:
        print(f"[skip] {why}")
        return "skipped"
    if not RateLimiter("blocks", args.max_blocks_per_hour, 3600).allow("all"):
        notify.send(f"netops: block limit of {args.max_blocks_per_hour}/hour reached, not blocking {ip}. "
                    "Check for an attack wave or a noisy rule.")
        return "rate-limited"
    summary = ", ".join(sigs[:5])
    if dry_run() or router is None:
        print(f"[dry-run] would block {ip} for {args.timeout} ({summary})")
        result = "dry-run"
    else:
        try:
            result = router.block(args.list, ip, args.timeout, f"netops: {summary}"[:200])
        except (HttpError, OSError) as exc:
            notify.send(f"netops: FAILED to block {ip} on {router.host}: {exc}")
            return "error"
    if result in ("added", "dry-run"):
        ticket.open_ticket(f"block:{ip}", f"Blocked {ip} after IDS alerts",
                           f"Source {ip} was added to address list '{args.list}' for {args.timeout}.\n"
                           f"Signatures: {summary}\nUnblock: /ip firewall address-list remove "
                           f"[find list={args.list} address={ip}]")
        notify.send(f"netops: blocked {ip} for {args.timeout} ({summary})")
    return result


def follow(path: Path, from_start: bool, once: bool):
    """Yield new lines, like tail -F (survives log rotation)."""
    while not path.exists():
        time.sleep(2)
    f = path.open(encoding="utf-8", errors="replace")
    inode = os.fstat(f.fileno()).st_ino
    if not from_start:
        f.seek(0, os.SEEK_END)
    try:
        while True:
            line = f.readline()
            if line:
                yield line
                continue
            if once:
                return
            time.sleep(0.5)
            try:
                if path.stat().st_ino != inode:
                    f.close()
                    f = path.open(encoding="utf-8", errors="replace")
                    inode = os.fstat(f.fileno()).st_ino
            except FileNotFoundError:
                pass
    finally:
        f.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", required=True, help="eve.json (Suricata) or alert_json.txt (Snort 3)")
    ap.add_argument("--threshold", type=int, default=5, help="alerts from one IP that trigger a block")
    ap.add_argument("--window", type=int, default=60, help="seconds")
    ap.add_argument("--instant-severity", type=int, default=1, help="block right away at this severity or higher (1 = highest)")
    ap.add_argument("--list", default="netops-blocked", help="MikroTik address list")
    ap.add_argument("--timeout", default="1d", help="how long the block lasts (RouterOS format: 1h, 1d)")
    ap.add_argument("--max-blocks-per-hour", type=int, default=20)
    ap.add_argument("--from-start", action="store_true", help="read the whole file, not only new lines")
    ap.add_argument("--once", action="store_true", help="stop at the end of the file")
    args = ap.parse_args()

    router = None if dry_run() else RouterOS.from_env()
    det = Detector(args.threshold, args.window, args.instant_severity)
    print(f"watching {args.file} (threshold {args.threshold} in {args.window}s, dry run: {dry_run()})")
    for line in follow(Path(args.file), args.from_start, args.once):
        event = parse_event(line)
        if event and det.feed(event, time.time()):
            respond(event["src"], det.signatures(event["src"]), args, router)
    return 0


if __name__ == "__main__":
    sys.exit(main())
