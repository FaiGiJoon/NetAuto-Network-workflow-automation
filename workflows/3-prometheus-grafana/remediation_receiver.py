#!/usr/bin/env python3
"""Receives Alertmanager webhooks and decides what to do with each alert.

  DeviceDown with poe_switch/poe_port labels -> power-cycle the PoE port (rate limited)
  InterfaceErrors / LinkSaturated            -> read the interface on the MikroTik, ticket with the numbers
  DeviceDown (no PoE), InterfaceDown         -> ticket + notification
  resolved                                   -> notification

Set REMEDIATION_TOKEN to require "Authorization: Bearer <token>" (configure the
same token in alertmanager.yml under http_config.authorization).

    python remediation_receiver.py --listen 0.0.0.0 --port 9095
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))

from netops import notify, ticket  # noqa: E402
from netops.actions import poe_restart  # noqa: E402
from netops.http import HttpError  # noqa: E402
from netops.mikrotik import RouterOS  # noqa: E402
from netops.safety import dry_run  # noqa: E402


def diagnostics(labels: dict, router_factory=RouterOS.from_env) -> str:
    host, ifname = labels.get("instance"), labels.get("ifName")
    if not host or not ifname or dry_run():
        return "(no diagnostics collected)"
    try:
        stats = router_factory(host=host).interface_stats(ifname)
    except (HttpError, KeyError, OSError) as exc:
        return f"(could not read {ifname} on {host}: {exc})"
    keys = ["running", "rx-error", "tx-error", "rx-drop", "tx-drop", "fp-rx-byte", "fp-tx-byte",
            "link-downs", "last-link-down-time", "last-link-up-time"]
    return "\n".join(f"{k}: {stats[k]}" for k in keys if k in stats) or json.dumps(stats)


def handle_alert(alert: dict, router_factory=RouterOS.from_env) -> str:
    labels, ann = alert.get("labels", {}), alert.get("annotations", {})
    name = labels.get("alertname", "?")
    who = labels.get("device") or labels.get("instance", "?")
    summary = ann.get("summary", f"{name} on {who}")

    if alert.get("status") == "resolved":
        notify.send(f"netops: RESOLVED {summary}")
        return "resolved"

    if name == "DeviceDown" and labels.get("poe_port"):
        return "poe:" + poe_restart(who, labels.get("poe_switch", ""), labels["poe_port"])

    if name in ("InterfaceErrors", "LinkSaturated"):
        diag = diagnostics(labels, router_factory)
        ticket.open_ticket(f"{name}:{labels.get('instance')}:{labels.get('ifName')}", summary,
                           f"{summary}\n\nInterface details at the time of the alert:\n{diag}")
        notify.send(f"netops: {summary}")
        return "ticket+diag"

    ticket.open_ticket(f"{name}:{labels.get('instance')}:{labels.get('ifName', '')}", summary,
                       f"{summary}\n\nLabels: {json.dumps(labels, indent=2)}")
    notify.send(f"netops: {summary}")
    return "ticket"


def handle_payload(payload: dict, router_factory=RouterOS.from_env) -> list[str]:
    return [handle_alert(a, router_factory) for a in payload.get("alerts", [])]


class Handler(BaseHTTPRequestHandler):
    def _reply(self, code: int, body: dict):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            return self._reply(200, {"ok": True, "dry_run": dry_run()})
        self._reply(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/alert":
            return self._reply(404, {"error": "not found"})
        token = os.environ.get("REMEDIATION_TOKEN")
        if token and not hmac.compare_digest(self.headers.get("Authorization", ""), f"Bearer {token}"):
            return self._reply(401, {"error": "unauthorized"})
        length = int(self.headers.get("Content-Length", 0))
        if length > 1_000_000:
            return self._reply(413, {"error": "too large"})
        try:
            payload = json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            return self._reply(400, {"error": "bad json"})
        self._reply(200, {"results": handle_payload(payload)})


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--listen", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9095)
    a = ap.parse_args()
    print(f"remediation receiver on {a.listen}:{a.port} (dry run: {dry_run()})")
    ThreadingHTTPServer((a.listen, a.port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
