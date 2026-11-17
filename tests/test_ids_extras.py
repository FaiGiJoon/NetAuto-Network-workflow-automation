"""Tests for 'netops-ids install-suricata' (the config edits) and
'netops-ids zabbix-setup' (against a fake Zabbix API).

Run with:  python -m unittest discover -s tests
"""

import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "apps"))

import _suricata  # noqa: E402
from _runtime import Asker  # noqa: E402

SURICATA_YAML = """vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
af-packet:
  - interface: eth0
    cluster-id: 99
  - interface: default
pcap:
  - interface: eth0
"""


class SuricataConfigTests(unittest.TestCase):
    def test_home_net(self):
        out = _suricata.set_home_net(SURICATA_YAML, ["192.168.88.0/24"])
        self.assertIn('HOME_NET: "[192.168.88.0/24]"', out)
        self.assertIn('EXTERNAL_NET: "!$HOME_NET"', out)

    def test_af_packet_interface_only_first(self):
        out = _suricata.set_af_packet_interface(SURICATA_YAML, "enx00e04c680001")
        self.assertIn("af-packet:\n  - interface: enx00e04c680001", out)
        self.assertIn("  - interface: default", out)
        self.assertIn("pcap:\n  - interface: eth0", out)          # pcap section untouched

    def test_missing_sections_are_reported(self):
        with self.assertRaises(ValueError):
            _suricata.set_home_net("nothing here", ["10.0.0.0/8"])
        with self.assertRaises(ValueError):
            _suricata.set_af_packet_interface("vars: {}", "eth1")

    def test_defaults_file(self):
        self.assertEqual(_suricata.set_defaults_iface("RUN=yes\nIFACE=eth0\n", "eth1"), "RUN=yes\nIFACE=eth1\n")
        self.assertIn("IFACE=eth1", _suricata.set_defaults_iface("RUN=yes\n", "eth1"))

    def test_home_net_suggestion(self):
        ifaces = [{"name": "enp1s0", "ipv4": ["192.168.88.10/24"]}, {"name": "enx1", "ipv4": []},
                  {"name": "wan0", "ipv4": ["84.10.1.2/24"]}]
        self.assertEqual(_suricata.suggest_home_net(ifaces), ["192.168.88.0/24"])
        self.assertEqual(len(_suricata.suggest_home_net([])), 3)

    def test_install_refuses_without_root(self):
        if os.name == "nt" or os.geteuid() == 0:
            self.skipTest("only meaningful as a normal user on Linux")
        with self.assertRaises(SystemExit):
            _suricata.install(Asker(True))


class FakeZabbix(BaseHTTPRequestHandler):
    state: dict = {}

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        method, params, st = body["method"], body["params"], self.state
        st.setdefault("calls", []).append(method)
        if method != "apiinfo.version" and self.headers.get("Authorization") != "Bearer good-token":
            return self.reply(body, error={"code": -32602, "message": "Not authorised."})
        kind, _, verb = method.partition(".")
        store = st.setdefault(kind, [])
        idkey = {"hostgroup": "groupid", "script": "scriptid", "action": "actionid", "host": "hostid",
                 "template": "templateid", "usermacro": "hostmacroid"}.get(kind)
        if method == "apiinfo.version":
            return self.reply(body, "7.0.5")
        if verb == "get":
            flt = params.get("filter", {})
            rows = [r for r in store if all(r.get(k) == v for k, v in flt.items())]
            if "hostids" in params:
                rows = [r for r in rows if r.get("hostid") == params["hostids"]]
            return self.reply(body, rows)
        if verb == "create":
            row = {**params, idkey: str(len(store) + 1)}
            store.append(row)
            if kind == "host":
                for m in params.get("macros", []):
                    st.setdefault("usermacro", []).append({**m, "hostid": row["hostid"],
                                                           "hostmacroid": f"m{len(st['usermacro']) + 1}"})
            return self.reply(body, {idkey + "s": [row[idkey]]})
        if verb == "update":
            for r in store:
                if r[idkey] == params[idkey]:
                    r.update(params)
            return self.reply(body, {idkey + "s": [params[idkey]]})
        return self.reply(body, error={"code": -32601, "message": f"unknown {method}"})

    def reply(self, req, result=None, error=None):
        out = {"jsonrpc": "2.0", "id": req["id"], **({"error": error} if error else {"result": result})}
        data = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class ZabbixSetupTests(unittest.TestCase):
    def setUp(self):
        self.state = {"template": [{"templateid": "10564", "host": "ICMP Ping"}]}
        handler = type("Z", (FakeZabbix,), {"state": self.state})
        self.server = HTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def run_setup(self, token="good-token"):
        import _zabbix
        devices = [{"name": "cam-utr-11", "ip": "10.10.20.11", "switch": "10.255.10.1", "port": "ether7"}]
        env = {"ZABBIX_URL": self.url, "ZABBIX_TOKEN": token, "ZABBIX_POE_DEVICES": json.dumps(devices)}
        with mock.patch.dict(os.environ, env):
            return _zabbix.setup(Asker(True), "/opt/netops/netops-ids")

    def test_creates_everything_once(self):
        self.run_setup()
        self.run_setup()                                   # second run must not duplicate
        self.assertEqual(len(self.state["hostgroup"]), 1)
        self.assertEqual(len(self.state["script"]), 1)
        self.assertEqual(len(self.state["action"]), 1)
        self.assertEqual(len(self.state["host"]), 1)
        script = self.state["script"][0]
        self.assertEqual(script["command"], "/opt/netops/netops-ids poe-restart --device {HOST.NAME} "
                                            "--switch {$POE_SWITCH} --port {$POE_PORT}")
        self.assertEqual((script["scope"], script["execute_on"]), (1, 1))
        action = self.state["action"][0]
        self.assertEqual(action["operations"][0]["opcommand"]["scriptid"], script["scriptid"])
        conds = {c["conditiontype"]: c["value"] for c in action["filter"]["conditions"]}
        self.assertEqual(conds, {3: "Unavailable by ICMP ping", 0: self.state["hostgroup"][0]["groupid"]})
        host = self.state["host"][0]
        self.assertEqual(host["templates"], [{"templateid": "10564"}])
        macros = {m["macro"]: m["value"] for m in self.state["usermacro"]}
        self.assertEqual(macros, {"{$POE_SWITCH}": "10.255.10.1", "{$POE_PORT}": "ether7"})

    def test_bad_token_is_a_clear_error(self):
        with self.assertRaises(SystemExit) as ctx:
            self.run_setup(token="wrong")
        self.assertIn("Not authorised", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
