"""Tests for the workflows in workflows/. A small fake server stands in for the
MikroTik REST API, CrowdSec, AbuseIPDB, OPNsense and TheHive, so the scripts make
real HTTP calls without touching real devices.

Run with:  python -m unittest discover -s tests
"""

import importlib.util
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from urllib.parse import parse_qs, urlparse

import yaml

ROOT = Path(__file__).resolve().parent.parent
WF = ROOT / "workflows"
sys.path.insert(0, str(WF / "common"))

from netops.mikrotik import RouterOS  # noqa: E402
from netops.safety import RateLimiter, may_block  # noqa: E402


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


watcher = load("alert_watcher", WF / "1-ids-zabbix-autoremediate/alert_watcher.py")
receiver = load("remediation_receiver", WF / "3-prometheus-grafana/remediation_receiver.py")
bouncer = load("crowdsec_bouncer", WF / "4-security-onion-crowdsec/crowdsec_mikrotik_bouncer.py")
soar = load("soar", WF / "2-soc-wazuh-thehive/custom-netops-soar.py")


# ------------------------------------------------------------ fake server

class Fake:
    """In-memory state of all fake services."""

    def __init__(self):
        self.address_list = []          # MikroTik /ip/firewall/address-list
        self.poe_cycles = []            # MikroTik power-cycle calls
        self.interfaces = {"ether2": {".id": "*2", "name": "ether2", "running": "true",
                                      "rx-error": "1532", "tx-error": "0", "link-downs": "7"}}
        self.crowdsec = {"new": [], "deleted": []}
        self.abuse_score = 0
        self.opnsense = []
        self.thehive = []
        self._id = 0

    def next_id(self):
        self._id += 1
        return f"*{self._id:X}"


class Handler(BaseHTTPRequestHandler):
    fake: Fake = None

    def log_message(self, *args):
        pass

    def _send(self, obj, code=200):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        url = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        f = self.fake
        if url.path == "/rest/ip/firewall/address-list":
            rows = [r for r in f.address_list if all(r.get(k) == v for k, v in q.items())]
            return self._send(rows)
        if url.path == "/rest/interface":
            return self._send([v for v in f.interfaces.values() if v["name"] == q.get("name")])
        if url.path == "/v1/decisions/stream":
            if self.headers.get("X-Api-Key") != "bouncer-key":
                return self._send({"message": "forbidden"}, 403)
            out, f.crowdsec = f.crowdsec, {"new": [], "deleted": []}
            return self._send(out)
        if url.path == "/api/v2/check":
            return self._send({"data": {"ipAddress": q["ipAddress"], "abuseConfidenceScore": f.abuse_score}})
        self._send({"error": url.path}, 404)

    def do_PUT(self):
        if self.path == "/rest/ip/firewall/address-list":
            row = {".id": self.fake.next_id(), **self._body()}
            self.fake.address_list.append(row)
            return self._send(row, 201)
        self._send({"error": self.path}, 404)

    def do_DELETE(self):
        if self.path.startswith("/rest/ip/firewall/address-list/"):
            item = self.path.rsplit("/", 1)[1]
            before = len(self.fake.address_list)
            self.fake.address_list = [r for r in self.fake.address_list if r[".id"] != item]
            return self._send({}, 204 if len(self.fake.address_list) < before else 404)
        self._send({"error": self.path}, 404)

    def do_POST(self):
        body = self._body()
        if self.path == "/rest/interface/ethernet/poe/power-cycle":
            self.fake.poe_cycles.append(body)
            return self._send([])
        if self.path.startswith("/api/firewall/alias_util/add/"):
            self.fake.opnsense.append((self.path.rsplit("/", 1)[1], body["address"]))
            return self._send({"status": "done"})
        if self.path == "/api/v1/alert":
            self.fake.thehive.append(body)
            return self._send({"_id": f"~{len(self.fake.thehive)}"}, 201)
        self._send({"error": self.path}, 404)


class WithServer(unittest.TestCase):
    def setUp(self):
        self.fake = Fake()
        handler = type("H", (Handler,), {"fake": self.fake})
        self.server = HTTPServer(("127.0.0.1", 0), handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.tmp = tempfile.TemporaryDirectory()
        base = f"http://127.0.0.1:{self.port}"
        self.env = mock.patch.dict(os.environ, {
            "NETOPS_STATE_DIR": self.tmp.name, "NETOPS_DRY_RUN": "false",
            "MIKROTIK_HOST": "127.0.0.1", "MIKROTIK_PORT": str(self.port), "MIKROTIK_SCHEME": "http",
            "MIKROTIK_USER": "netops", "MIKROTIK_PASSWORD": "x",
            "CROWDSEC_LAPI_URL": base, "CROWDSEC_BOUNCER_KEY": "bouncer-key",
            "ABUSEIPDB_URL": base, "ABUSEIPDB_KEY": "k",
            "OPNSENSE_URL": base, "OPNSENSE_KEY": "k", "OPNSENSE_SECRET": "s",
            "THEHIVE_URL": base, "THEHIVE_KEY": "k",
        }, clear=False)
        self.env.start()
        for var in ("TEAMS_WEBHOOK_URL", "SLACK_WEBHOOK_URL", "TELEGRAM_BOT_TOKEN",
                    "JIRA_URL", "GITLAB_URL", "TOPDESK_URL", "NETOPS_ALLOWLIST"):
            os.environ.pop(var, None)
        self.router = RouterOS.from_env()

    def tearDown(self):
        self.env.stop()
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()


# ------------------------------------------------------------------ tests

class SafetyTests(unittest.TestCase):
    def test_private_and_loopback_never_blocked(self):
        for ip in ("10.1.2.3", "192.168.1.1", "172.16.5.5", "127.0.0.1"):
            self.assertFalse(may_block(ip)[0], ip)

    def test_public_ip_may_be_blocked(self):
        self.assertTrue(may_block("203.0.113.7")[0])

    def test_custom_allowlist(self):
        with mock.patch.dict(os.environ, {"NETOPS_ALLOWLIST": "203.0.113.0/24"}):
            self.assertFalse(may_block("203.0.113.7")[0])

    def test_garbage_is_refused(self):
        self.assertFalse(may_block("not-an-ip")[0])

    def test_rate_limiter(self):
        with tempfile.TemporaryDirectory() as d:
            rl = RateLimiter("t", 2, 60, d)
            self.assertTrue(rl.allow("x", now=100))
            self.assertTrue(rl.allow("x", now=101))
            self.assertFalse(rl.allow("x", now=102))
            self.assertTrue(rl.allow("x", now=200))       # window passed
            self.assertTrue(RateLimiter("t", 2, 60, d).allow("y", now=102))   # other key


class AlertWatcherTests(WithServer):
    def args(self, **kw):
        base = dict(list="netops-blocked", timeout="1d", max_blocks_per_hour=20)
        return SimpleNamespace(**{**base, **kw})

    def test_parse_suricata_and_snort(self):
        sur = watcher.parse_event(json.dumps({"event_type": "alert", "src_ip": "203.0.113.7",
                                              "dest_ip": "10.0.0.5", "alert": {"signature": "ET SCAN", "severity": 2}}))
        self.assertEqual(sur, {"src": "203.0.113.7", "dst": "10.0.0.5", "sig": "ET SCAN", "severity": 2})
        snort = watcher.parse_event(json.dumps({"src_addr": "198.51.100.9", "dst_addr": "10.0.0.5",
                                                "msg": "SSH brute force", "priority": 1}))
        self.assertEqual(snort["severity"], 1)
        self.assertIsNone(watcher.parse_event("not json"))
        self.assertIsNone(watcher.parse_event(json.dumps({"event_type": "flow"})))

    def test_threshold_window_and_fire_once(self):
        det = watcher.Detector(threshold=3, window=60)
        ev = {"src": "203.0.113.7", "sig": "x", "severity": 3}
        self.assertFalse(det.feed(ev, 0))
        self.assertFalse(det.feed(ev, 10))
        self.assertTrue(det.feed(ev, 20))           # 3rd within 60 s
        self.assertFalse(det.feed(ev, 21))          # already fired
        det2 = watcher.Detector(threshold=3, window=60)
        det2.feed(ev, 0), det2.feed(ev, 10)
        self.assertFalse(det2.feed(ev, 100))        # first two expired

    def test_highest_severity_blocks_at_once(self):
        det = watcher.Detector(threshold=99, window=60)
        self.assertTrue(det.feed({"src": "203.0.113.8", "sig": "exploit", "severity": 1}, 0))

    def test_block_on_router_once(self):
        self.assertEqual(watcher.respond("203.0.113.7", ["ET SCAN"], self.args(), self.router), "added")
        self.assertEqual(watcher.respond("203.0.113.7", ["ET SCAN"], self.args(), self.router), "exists")
        self.assertEqual(len(self.fake.address_list), 1)
        row = self.fake.address_list[0]
        self.assertEqual((row["list"], row["address"], row["timeout"]), ("netops-blocked", "203.0.113.7", "1d"))

    def test_private_ip_not_blocked(self):
        self.assertEqual(watcher.respond("10.0.0.99", ["x"], self.args(), self.router), "skipped")
        self.assertEqual(self.fake.address_list, [])

    def test_block_rate_limit(self):
        a = self.args(max_blocks_per_hour=2)
        watcher.respond("203.0.113.1", ["x"], a, self.router)
        watcher.respond("203.0.113.2", ["x"], a, self.router)
        self.assertEqual(watcher.respond("203.0.113.3", ["x"], a, self.router), "rate-limited")
        self.assertEqual(len(self.fake.address_list), 2)

    def test_dry_run_changes_nothing(self):
        with mock.patch.dict(os.environ, {"NETOPS_DRY_RUN": "true"}):
            self.assertEqual(watcher.respond("203.0.113.7", ["x"], self.args(), self.router), "dry-run")
        self.assertEqual(self.fake.address_list, [])

    def test_end_to_end_from_file(self):
        lines = [json.dumps({"event_type": "alert", "src_ip": "198.51.100.20", "dest_ip": "10.0.0.5",
                             "alert": {"signature": f"ET SCAN {i}", "severity": 3}}) for i in range(5)]
        path = Path(self.tmp.name) / "eve.json"
        path.write_text("\n".join(lines) + "\n")
        det = watcher.Detector(5, 60)
        for line in watcher.follow(path, from_start=True, once=True):
            ev = watcher.parse_event(line)
            if ev and det.feed(ev, 0):
                watcher.respond(ev["src"], det.signatures(ev["src"]), self.args(), self.router)
        self.assertEqual([r["address"] for r in self.fake.address_list], ["198.51.100.20"])


class PoeAndReceiverTests(WithServer):
    def test_poe_restart_then_limit(self):
        from netops.actions import poe_restart
        for _ in range(3):
            self.assertEqual(poe_restart("cam-11", "127.0.0.1", "ether7", router=self.router), "restarted")
        self.assertEqual(poe_restart("cam-11", "127.0.0.1", "ether7", router=self.router), "limit")
        self.assertEqual(self.fake.poe_cycles, [{"numbers": "ether7", "duration": "5s"}] * 3)

    def test_poe_without_port(self):
        from netops.actions import poe_restart
        self.assertEqual(poe_restart("cam-11", "127.0.0.1", "{$POE_PORT}", router=self.router), "no-port")

    def test_receiver_device_down_restarts_poe(self):
        factory = lambda host=None: self.router  # noqa: E731
        payload = {"alerts": [{"status": "firing", "labels": {
            "alertname": "DeviceDown", "device": "cam-utr-11", "poe_switch": "127.0.0.1", "poe_port": "ether7"}}]}
        with mock.patch.object(RouterOS, "from_env", classmethod(lambda cls, host=None: self.router)):
            self.assertEqual(receiver.handle_payload(payload, factory), ["poe:restarted"])
        self.assertEqual(len(self.fake.poe_cycles), 1)

    def test_receiver_interface_errors_collects_diagnostics(self):
        factory = lambda host=None: self.router  # noqa: E731
        diag = receiver.diagnostics({"instance": "127.0.0.1", "ifName": "ether2"}, factory)
        self.assertIn("rx-error: 1532", diag)
        alert = {"status": "firing", "labels": {"alertname": "InterfaceErrors", "instance": "127.0.0.1",
                                                "ifName": "ether2"}, "annotations": {"summary": "errors"}}
        self.assertEqual(receiver.handle_alert(alert, factory), "ticket+diag")

    def test_receiver_resolved(self):
        self.assertEqual(receiver.handle_alert({"status": "resolved", "labels": {"alertname": "DeviceDown"}}),
                         "resolved")


class CrowdSecTests(WithServer):
    def decision(self, value, scope="Ip", origin="crowdsec", duration="3h59m12.5s", type_="ban"):
        return {"value": value, "scope": scope, "origin": origin, "duration": duration,
                "type": type_, "scenario": "crowdsecurity/ssh-bf"}

    def make(self, **kw):
        args = dict(include_community=False, max_entries=100)
        args.update(kw)
        return bouncer.Bouncer(self.router, os.environ["CROWDSEC_LAPI_URL"], "bouncer-key",
                               "crowdsec-blocked", args["include_community"], args["max_entries"])

    def test_go_duration(self):
        self.assertEqual(bouncer.go_duration_seconds("3h59m12.5s"), 14352)
        self.assertEqual(bouncer.go_duration_seconds("150ms"), 0)
        self.assertEqual(bouncer.go_duration_seconds("-5s"), 0)

    def test_filters(self):
        ok = lambda d, c=False: bouncer.acceptable(d, c)[0]  # noqa: E731
        self.assertTrue(ok(self.decision("203.0.113.7")))
        self.assertFalse(ok(self.decision("203.0.113.7", origin="CAPI")))           # community off
        self.assertTrue(ok(self.decision("203.0.113.7", origin="CAPI"), True))
        self.assertFalse(ok(self.decision("10.0.0.1")))                              # private
        self.assertFalse(ok(self.decision("203.0.113.7", type_="captcha")))
        self.assertTrue(ok(self.decision("198.51.100.0/24", scope="Range")))
        self.assertFalse(ok(self.decision("8.0.0.0/8", scope="Range")))              # too wide
        self.assertFalse(ok(self.decision("10.0.0.0/16", scope="Range")))            # allowlist

    def test_full_sync_then_deltas(self):
        # A ban from an earlier run that CrowdSec has lifted meanwhile, and one manual entry.
        self.fake.address_list = [
            {".id": "*A", "list": "crowdsec-blocked", "address": "198.51.100.50", "comment": "crowdsec: old"},
            {".id": "*B", "list": "crowdsec-blocked", "address": "198.51.100.60", "comment": "added by hand"},
        ]
        b = self.make()
        b.load_existing()
        self.fake.crowdsec = {"new": [self.decision("203.0.113.7"), self.decision("10.0.0.5")], "deleted": []}
        result = b.apply(b.fetch(startup=True), full=True)
        self.assertEqual((result["added"], result["removed"], result["skipped"]), (1, 1, 1))
        addresses = {r["address"]: r for r in self.fake.address_list}
        self.assertIn("203.0.113.7", addresses)
        self.assertEqual(addresses["203.0.113.7"]["timeout"], "14352s")
        self.assertNotIn("198.51.100.50", addresses)          # lifted ban removed
        self.assertIn("198.51.100.60", addresses)             # manual entry untouched
        # Next poll: CrowdSec lifts the ban.
        self.fake.crowdsec = {"new": [], "deleted": [self.decision("203.0.113.7")]}
        result = b.apply(b.fetch(startup=False), full=False)
        self.assertEqual(result["removed"], 1)
        self.assertNotIn("203.0.113.7", {r["address"] for r in self.fake.address_list})

    def test_cap(self):
        b = self.make(max_entries=2)
        self.fake.crowdsec = {"new": [self.decision(f"203.0.113.{i}") for i in range(1, 5)], "deleted": []}
        result = b.apply(b.fetch(startup=True), full=True)
        self.assertEqual((result["added"], result["capped"]), (2, 2))

    def test_wrong_key_is_refused(self):
        b = bouncer.Bouncer(self.router, os.environ["CROWDSEC_LAPI_URL"], "wrong", "x", False, 10)
        with self.assertRaises(Exception):
            b.fetch(startup=True)


class SoarTests(WithServer):
    alert = {"id": "1700000000.123", "rule": {"id": "100200", "level": 12, "description": "Suricata high severity"},
             "agent": {"name": "sensor-01"}, "data": {"src_ip": "203.0.113.7"}}

    def test_bad_reputation_is_blocked(self):
        self.fake.abuse_score = 92
        out = soar.handle(self.alert)
        self.assertTrue(out["blocked"])
        self.assertEqual(self.fake.opnsense, [("netops_blocked", "203.0.113.7")])
        self.assertEqual(self.fake.thehive[0]["observables"], [{"dataType": "ip", "data": "203.0.113.7"}])
        self.assertIn("auto-blocked", self.fake.thehive[0]["tags"])
        self.assertEqual(self.fake.thehive[0]["severity"], 3)

    def test_good_reputation_only_review(self):
        self.fake.abuse_score = 5
        out = soar.handle(self.alert)
        self.assertFalse(out["blocked"])
        self.assertEqual(self.fake.opnsense, [])
        self.assertIn("review", self.fake.thehive[0]["tags"])

    def test_private_source_ignored(self):
        out = soar.handle({**self.alert, "data": {"src_ip": "192.168.1.10"}})
        self.assertFalse(out["blocked"])
        self.assertEqual(self.fake.thehive, [])


class ConfigFileTests(unittest.TestCase):
    def test_yaml_files_parse(self):
        files = list((WF / "3-prometheus-grafana").rglob("*.yml")) + [WF / "6-homelab-uptimekuma-n8n/docker-compose.yml"]
        for f in files:
            with self.subTest(f=f.name):
                self.assertIsNotNone(yaml.safe_load(f.read_text()))

    def test_alert_rules_have_names_and_expressions(self):
        rules = yaml.safe_load((WF / "3-prometheus-grafana/prometheus/rules/network.yml").read_text())
        names = [r["alert"] for g in rules["groups"] for r in g["rules"]]
        self.assertEqual(names, ["DeviceDown", "PacketLoss", "InterfaceDown", "InterfaceErrors", "LinkSaturated"])

    def test_dashboard_json(self):
        dash = json.loads((WF / "3-prometheus-grafana/grafana/dashboards/network-overview.json").read_text())
        self.assertEqual(dash["uid"], "netops-overview")
        self.assertTrue(all(p["targets"] for p in dash["panels"]))

    def test_n8n_workflow_connections_point_to_real_nodes(self):
        wf = json.loads((WF / "6-homelab-uptimekuma-n8n/n8n-poe-restart-workflow.json").read_text())
        names = {n["name"] for n in wf["nodes"]}
        for src, conn in wf["connections"].items():
            self.assertIn(src, names)
            for branch in conn["main"]:
                for target in branch:
                    self.assertIn(target["node"], names)


if __name__ == "__main__":
    unittest.main()
