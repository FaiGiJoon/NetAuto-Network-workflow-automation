"""Tests for the NetAuto console (apps/_gui.py, _toolkit.py, _jobs.py, _diag.py):
the guards (local Host, session token, no path traversal, safe inputs), the API,
the background jobs, the parsers for every tool's output, diagnostics against a
fake Zabbix, and the settings file.

Run with:  python -m unittest discover -s tests
"""

import http.client
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "apps"))

import _diag  # noqa: E402
import _toolkit as tk  # noqa: E402
from _gui import _host_is_local, make_server  # noqa: E402


class ServerCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.env = mock.patch.dict(os.environ, {"NETOPS_CONFIG": str(Path(cls.tmp.name) / "env"),
                                               "NETOPS_STATE_DIR": cls.tmp.name})
        cls.env.start()
        cls.state = mock.patch("_runtime.default_state_dir", return_value=Path(cls.tmp.name))
        cls.state.start()
        cls.server = make_server(ROOT, ROOT / "gui", ROOT / "scripts", "test", port=0)
        cls.port = cls.server.server_address[1]
        cls.token = cls.server.api.token
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.state.stop()
        cls.env.stop()
        cls.tmp.cleanup()

    def request(self, method, path, body=None, headers=None, token=True):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        hdrs = {"Host": f"127.0.0.1:{self.port}"}
        if token:
            hdrs["X-NetAuto-Token"] = self.token
        hdrs.update(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            hdrs.setdefault("Content-Type", "application/json")
        conn.request(method, path, body=data, headers=hdrs)
        r = conn.getresponse()
        payload = r.read()
        conn.close()
        return r.status, r.getheader("Content-Type", ""), payload

    def api(self, method, path, body=None):
        status, _, payload = self.request(method, path, body)
        return status, json.loads(payload)

    def run_job(self, kind, params=None, timeout=60):
        status, job = self.api("POST", "/api/jobs", {"kind": kind, "params": params or {}})
        self.assertEqual(status, 200, job)
        deadline = time.time() + timeout
        while time.time() < deadline:
            _, view = self.api("GET", f"/api/jobs/{job['id']}")
            if view["status"] != "running":
                return view
            time.sleep(0.2)
        self.fail(f"job {kind} did not finish")


class GuardTests(ServerCase):
    def test_page_carries_the_token(self):
        status, ctype, body = self.request("GET", "/", token=False)
        self.assertEqual(status, 200)
        self.assertIn("text/html", ctype)
        self.assertIn(f'content="{self.token}"'.encode(), body)
        for name in ("app.js", "tools.js", "scenarios.js", "icons.js", "styles.css"):
            self.assertEqual(self.request("GET", f"/{name}", token=False)[0], 200, name)

    def test_api_needs_the_token(self):
        self.assertEqual(self.request("GET", "/api/status", token=False)[0], 403)
        self.assertEqual(self.request("GET", "/api/status", headers={"X-NetAuto-Token": "wrong"}, token=False)[0], 403)
        self.assertEqual(self.request("POST", "/api/jobs", {"kind": "diagnostics"}, token=False)[0], 403)

    def test_no_path_traversal(self):
        for path in ("/../README.md", "/%2e%2e/README.md", "/../../etc/passwd", "/api/files/..%2fREADME.md"):
            self.assertIn(self.request("GET", path)[0], (403, 404), path)

    def test_rejects_foreign_host(self):
        status, _, _ = self.request("GET", "/api/status", headers={"Host": "evil.example:8765"})
        self.assertEqual(status, 403)

    def test_post_needs_json(self):
        status, _, _ = self.request("POST", "/api/validate", {}, headers={"Content-Type": "text/plain"})
        self.assertEqual(status, 415)

    def test_host_check(self):
        self.assertTrue(_host_is_local("127.0.0.1:8765"))
        self.assertTrue(_host_is_local("localhost"))
        self.assertTrue(_host_is_local("[::1]:8765"))
        self.assertFalse(_host_is_local("127.0.0.1.evil.example"))
        self.assertFalse(_host_is_local(None))

    def test_bad_inputs_never_reach_a_command(self):
        for kind, params in (("nmap", {"target": "-iL /etc/passwd"}), ("nmap", {"target": "10.0.0.0/8"}),
                             ("ping", {"target": "1.1.1.1; rm -rf /"}), ("ping", {"target": "192.168.1.0/24"}),
                             ("capture", {"interface": "-w /tmp/x"}), ("program", {"program": "netops-ids", "action": "run"}),
                             ("nope", {})):
            status, body = self.api("POST", "/api/jobs", {"kind": kind, "params": params})
            self.assertEqual(status, 400, (kind, params, body))
            self.assertFalse(body["ok"])


class ApiTests(ServerCase):
    def test_status_inventory_tools_netinfo(self):
        status, st = self.api("GET", "/api/status")
        self.assertEqual((status, st["version"]), (200, "test"))
        _, inv = self.api("GET", "/api/inventory")
        self.assertIn("utr-core-01", [d["name"] for d in inv["devices"]])
        _, tools = self.api("GET", "/api/tools")
        self.assertIn("nmap", tools["tools"])
        self.assertIn("discover", tools["nmap_profiles"])
        _, net = self.api("GET", "/api/netinfo")
        self.assertIn("hostname", net)

    def test_validate_and_plan(self):
        _, result = self.api("POST", "/api/validate", {})
        self.assertTrue(result["ok"], result["errors"])
        _, plan = self.api("POST", "/api/plan", {"base": ""})
        self.assertTrue(plan["ok"], plan.get("errors"))
        self.assertTrue(plan["devices"]["utr-core-01"]["commands"])
        status, body = self.api("POST", "/api/plan", {"base": "--output=/tmp/x"})
        self.assertEqual(status, 400)

    def test_git_status_job(self):
        if not tk.find_tool("git"):
            self.skipTest("git not installed")
        view = self.run_job("git-status")
        self.assertEqual(view["status"], "done", view)
        self.assertIn("is_repo", view["result"])

    def test_program_job_captures_output(self):
        view = self.run_job("program", {"program": "netops-soc", "action": "test"})
        self.assertEqual(view["status"], "done", view)
        self.assertTrue(any("203.0.113.7" in line for line in view["lines"]), view["lines"])

    def test_ping_job(self):
        if not tk.find_tool("ping"):
            self.skipTest("ping not installed")
        view = self.run_job("ping", {"target": "127.0.0.1", "count": 1})
        if view["status"] != "done":
            self.skipTest(f"ping not permitted here: {view['lines'][-1:]}")
        self.assertIn("loss_percent", view["result"])

    def test_cancel_and_debug_log(self):
        _, body = self.api("POST", "/api/debug/client", {"message": "test error from the browser", "detail": "stack"})
        self.assertTrue(body["ok"])
        _, log = self.api("GET", "/api/debug")
        self.assertTrue(any(i["source"] == "browser" and "test error" in i["message"] for i in log["log"]))
        _, missing = self.api("POST", "/api/jobs/000000000000/cancel", {})
        self.assertFalse(missing["ok"])
        self.assertEqual(self.api("GET", "/api/jobs/000000000000")[0], 404)

    def test_capture_files_are_guarded(self):
        self.assertEqual(self.request("GET", "/api/files/secret.txt")[0], 404)
        name = "capture-20260101-000000.pcapng"
        (Path(self.tmp.name) / "captures").mkdir(exist_ok=True)
        (Path(self.tmp.name) / "captures" / name).write_bytes(b"\x0a\x0d\x0d\x0a")
        status, ctype, body = self.request("GET", f"/api/files/{name}")
        self.assertEqual((status, body), (200, b"\x0a\x0d\x0d\x0a"))

    def test_settings_round_trip_never_returns_secrets(self):
        status, body = self.api("POST", "/api/settings", {"values": {"ZABBIX_URL": "http://zbx.local", "ZABBIX_TOKEN": "s3cret",
                                                                      "NOT_A_SETTING": "x"}})
        self.assertEqual(status, 200)
        self.assertEqual(body["saved"], ["ZABBIX_TOKEN", "ZABBIX_URL"])
        _, view = self.api("GET", "/api/settings")
        fields = {f["key"]: f for f in view["fields"]}
        self.assertEqual(fields["ZABBIX_URL"]["value"], "http://zbx.local")
        self.assertTrue(fields["ZABBIX_TOKEN"]["set"])
        self.assertEqual(fields["ZABBIX_TOKEN"]["value"], "")
        self.assertNotIn(b"s3cret", self.request("GET", "/api/settings")[2])
        status, _ = self.api("POST", "/api/settings", {"values": {"ZABBIX_URL": "a\nb"}})
        self.assertEqual(status, 400)
        self.api("POST", "/api/settings", {"values": {"ZABBIX_URL": "", "ZABBIX_TOKEN": ""}})


class FakeZabbix(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        authed = self.headers.get("Authorization") == "Bearer good"
        if req["method"] == "apiinfo.version":
            out = {"result": "7.0.5"}
        elif not authed:
            out = {"error": {"message": "Not authorised.", "data": ""}}
        elif req["method"] == "host.get":
            out = {"result": "3"}
        else:
            out = {"result": [{"description": "cam down", "priority": "4", "lastchange": "1700000000",
                               "hosts": [{"name": "cam-utr-11"}]}]}
        body = json.dumps({"jsonrpc": "2.0", "id": req["id"], **out}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class DiagnosticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.zbx = HTTPServer(("127.0.0.1", 0), FakeZabbix)
        threading.Thread(target=cls.zbx.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.zbx.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.zbx.shutdown()
        cls.zbx.server_close()

    def services(self, **env):
        clean = {k: v for k, v in os.environ.items() if not any(k.startswith(p) for p in (
            "ZABBIX", "MIKROTIK", "GITLAB", "LIBRENMS", "NETBOX", "OXIDIZED", "THEHIVE", "OPNSENSE", "JIRA",
            "CROWDSEC", "ABUSEIPDB", "TELEGRAM", "TEAMS", "SLACK", "PROMETHEUS", "GRAFANA", "ALERTMANAGER", "UPTIME", "N8N"))}
        with mock.patch.dict(os.environ, {**clean, **env}, clear=True):
            return {c["name"]: c for c in _diag.service_checks()}

    def test_zabbix_ok_bad_token_and_not_configured(self):
        self.assertEqual(self.services()["Zabbix"]["status"], "skip")
        good = self.services(ZABBIX_URL=self.url, ZABBIX_TOKEN="good")["Zabbix"]
        self.assertEqual(good["status"], "ok", good)
        self.assertIn("3 hosts", good["detail"])
        bad = self.services(ZABBIX_URL=self.url, ZABBIX_TOKEN="wrong")["Zabbix"]
        self.assertEqual(bad["status"], "fail", bad)

    def test_unreachable_service_fails_with_a_fix(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            free = s.getsockname()[1]
        result = self.services(NETBOX_URL=f"http://127.0.0.1:{free}", NETBOX_TOKEN="x")["NetBox"]
        self.assertEqual(result["status"], "fail")
        self.assertTrue(result["fix"])

    def test_zabbix_overview(self):
        with mock.patch.dict(os.environ, {"ZABBIX_URL": self.url, "ZABBIX_TOKEN": "good"}):
            out = _diag.zabbix_overview()
        self.assertEqual(out["hosts"], 3)
        self.assertEqual(out["problems"][0]["severity"], "High")

    def test_system_and_tool_checks_have_a_status(self):
        for c in _diag.system_checks() + _diag.tool_checks():
            self.assertIn(c["status"], ("ok", "warn", "fail", "skip"), c)

    def test_redact(self):
        self.assertEqual(_diag.redact("https://user:ghp_abcdefghijklmnopqrstuvwxyz123@github.com/a/b"), "https://***@github.com/a/b")
        self.assertEqual(_diag.github_slug("git@github.com:Owner/repo.git"), "Owner/repo")
        self.assertEqual(_diag.github_slug("https://github.com/Owner/repo"), "Owner/repo")
        self.assertIsNone(_diag.github_slug("https://gitlab.com/a/b"))


class ParserTests(unittest.TestCase):
    def test_targets(self):
        self.assertEqual(tk.validate_target("192.168.1.7/24"), "192.168.1.0/24")
        self.assertEqual(tk.validate_target("router.local"), "router.local")
        for bad in ("-sV", "10.0.0.0/8", "a b", "1.1.1.1;id", "$(id)", ""):
            with self.assertRaises(tk.BadInput, msg=bad):
                tk.validate_target(bad)
        with self.assertRaises(tk.BadInput):
            tk.validate_target("192.168.1.0/24", allow_network=False)
        self.assertEqual(tk.validate_bpf("tcp port 443 and not host 10.0.0.1"), "tcp port 443 and not host 10.0.0.1")
        for bad in ("-w /tmp/x", "port 80; id", "`id`"):
            with self.assertRaises(tk.BadInput):
                tk.validate_bpf(bad)

    def test_interface_must_be_listed(self):
        known = [{"index": "1", "name": "eth0", "label": "eth0"}]
        self.assertEqual(tk.validate_interface("eth0", known), "1")
        with self.assertRaises(tk.BadInput):
            tk.validate_interface("2", known)

    def test_netsh_in_dutch_and_english(self):
        text = """
SSID 1 : Thuis
    Verificatie             : WPA2-Personal
    Versleuteling           : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:ff
         Signaal            : 80%
         Kanaal             : 36
SSID 2 : Cafe
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : 11:22:33:44:55:66
         Signal             : 31%
         Channel            : 6
"""
        nets = tk.parse_netsh(text)
        self.assertEqual([(n["ssid"], n["signal"], n["channel"], n["band"]) for n in nets],
                         [("Thuis", 80, 36, "5 GHz"), ("Cafe", 31, 6, "2.4 GHz")])
        self.assertEqual(tk.wifi_summary(nets)["open_or_wep"], ["Cafe"])

    def test_nmcli(self):
        nets = tk.parse_nmcli("*:Thuis:AA\\:BB\\:CC\\:DD\\:EE\\:FF:36:80:WPA2\n :Buren:11\\:22\\:33\\:44\\:55\\:66:6:40:")
        self.assertEqual(nets[0]["bssid"], "aa:bb:cc:dd:ee:ff")
        self.assertTrue(nets[0]["connected"])
        self.assertEqual(nets[1]["security"], "Open")

    def test_ping_and_trace(self):
        linux = "4 packets transmitted, 4 received, 0% packet loss, time 3004ms\n64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms"
        self.assertEqual(tk.parse_ping(linux)["loss_percent"], 0.0)
        dutch = "Antwoord van 8.8.8.8: bytes=32 tijd=12ms TTL=117\nverloren = 0 (0% verlies),"
        self.assertEqual(tk.parse_ping(dutch)["avg_ms"], 12.0)
        hops = tk.parse_trace("  1    <1 ms    <1 ms    <1 ms  192.168.1.1\n  2     *        *        *     Request timed out.\n"
                              "  3    12 ms    11 ms    12 ms  8.8.8.8")
        self.assertEqual([h["address"] for h in hops], ["192.168.1.1", "*", "8.8.8.8"])
        self.assertTrue(hops[1]["timeout"])

    def test_nmap_xml(self):
        xml = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="192.168.1.10" addrtype="ipv4"/><address addr="AA:BB:CC:00:11:22" addrtype="mac" vendor="Ubiquiti"/>
<hostnames><hostname name="ap-garden"/></hostnames><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6"/></port>
<port protocol="tcp" portid="80"><state state="closed"/><service name="http"/></port></ports></host>
<host><status state="down"/><address addr="192.168.1.11" addrtype="ipv4"/></host>
<runstats><finished summary="2 IP addresses (1 host up) scanned"/></runstats></nmaprun>"""
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
            f.write(xml)
        try:
            out = tk.parse_nmap_xml(Path(f.name))
        finally:
            os.unlink(f.name)
        self.assertEqual(len(out["hosts"]), 1)
        host = out["hosts"][0]
        self.assertEqual((host["ip"], host["vendor"], host["hostname"]), ("192.168.1.10", "Ubiquiti", "ap-garden"))
        self.assertEqual([(p["port"], p["version"]) for p in host["ports"]], [(22, "OpenSSH 9.6")])

    def test_commands_are_argument_lists(self):
        if tk.find_tool("nmap"):
            cmd = tk.nmap_cmd("192.168.1.0/24", "discover", Path("out.xml"))
            self.assertEqual(cmd[-1], "192.168.1.0/24")
            self.assertIn("-sn", cmd)
        if tk.find_tool("tshark"):
            cmd = tk.capture_cmd("1", 10, 5, "tcp port 443", Path("x.pcapng"))
            self.assertEqual(cmd[cmd.index("-f") + 1], "tcp port 443")


class PortFallbackTests(unittest.TestCase):
    """If the default port cannot be used, serve() falls back to a free port."""

    def _blocker(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        return s

    def test_falls_back_when_default_port_is_busy(self):
        import _gui
        blocker = self._blocker()
        busy = blocker.getsockname()[1]
        started = {}

        def fake_forever(self_server):
            started["port"] = self_server.server_address[1]
            raise KeyboardInterrupt

        try:
            with mock.patch.object(_gui, "DEFAULT_PORT", busy), \
                 mock.patch.object(_gui.ThreadingHTTPServer, "serve_forever", fake_forever), \
                 mock.patch("builtins.print"):
                rc = _gui.serve(ROOT, ROOT / "gui", ROOT / "scripts", "test", open_browser=False)
        finally:
            blocker.close()
        self.assertEqual(rc, 0)
        self.assertNotEqual(started["port"], busy)

    def test_explicit_busy_port_fails(self):
        import _gui
        blocker = self._blocker()
        try:
            with mock.patch("builtins.print"):
                rc = _gui.serve(ROOT, ROOT / "gui", ROOT / "scripts", "test",
                                port=blocker.getsockname()[1], open_browser=False)
        finally:
            blocker.close()
        self.assertEqual(rc, 1)


class ScenarioDataTests(unittest.TestCase):
    """Every event in gui/scenarios.js must point at nodes and steps that exist."""

    def test_scenarios_are_consistent(self):
        import re
        text = (ROOT / "gui" / "scenarios.js").read_text(encoding="utf-8")
        blocks = re.split(r'\n    \{\n      id: "', text)[1:]
        self.assertEqual(len(blocks), 6)
        for block in blocks:
            sid = block.split('"', 1)[0]
            nodes = set(re.findall(r'\{ id: "([^"]+)", label:', block))
            steps = len(re.findall(r"\{ title: ", block))
            for src, dst in re.findall(r'src: "([^"]+)", dst: "([^"]+)"', block):
                self.assertIn(src, nodes, sid)
                self.assertIn(dst, nodes, sid)
            for a, b in re.findall(r'\["([^"]+)", "([^"]+)"\]', block.split("links:", 1)[1].split("steps:", 1)[0]):
                self.assertIn(a, nodes, sid)
                self.assertIn(b, nodes, sid)
            for n in map(int, re.findall(r"\{ step: (\d+),", block)):
                self.assertLess(n, steps, sid)


@unittest.skipUnless(shutil.which("node"), "node not installed")
class JavaScriptSyntaxTests(unittest.TestCase):
    def test_gui_scripts_parse(self):
        import subprocess
        for name in ("app.js", "tools.js", "scenarios.js", "icons.js"):
            r = subprocess.run(["node", "--check", str(ROOT / "gui" / name)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f"{name}: {r.stderr}")


if __name__ == "__main__":
    unittest.main()
