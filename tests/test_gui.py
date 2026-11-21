"""Tests for the NetAuto console server (apps/_gui.py): static files, the
read-only JSON endpoints, and the guards (local Host only, no path traversal,
safe Git refs).

Run with:  python -m unittest discover -s tests
"""

import http.client
import json
import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "apps"))

from _gui import _host_is_local, make_server  # noqa: E402


class GuiServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = make_server(ROOT, ROOT / "gui", ROOT / "scripts", "test", port=0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        hdrs = {"Host": f"127.0.0.1:{self.port}", **(headers or {})}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            hdrs.setdefault("Content-Type", "application/json")
        conn.request(method, path, body=data, headers=hdrs)
        r = conn.getresponse()
        payload = r.read()
        conn.close()
        return r.status, r.getheader("Content-Type", ""), payload

    def test_serves_the_page_and_scripts(self):
        status, ctype, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", ctype)
        self.assertIn(b"NetAuto Console", body)
        for name in ("app.js", "scenarios.js", "icons.js", "styles.css"):
            status, _, _ = self.request("GET", f"/{name}")
            self.assertEqual(status, 200, name)

    def test_no_path_traversal(self):
        for path in ("/../README.md", "/%2e%2e/README.md", "/../../etc/passwd"):
            status, _, _ = self.request("GET", path)
            self.assertEqual(status, 404, path)

    def test_rejects_foreign_host(self):
        status, _, _ = self.request("GET", "/api/status", headers={"Host": "evil.example:8765"})
        self.assertEqual(status, 403)

    def test_status_and_inventory(self):
        status, _, body = self.request("GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["version"], "test")
        status, _, body = self.request("GET", "/api/inventory")
        inv = json.loads(body)
        self.assertTrue(inv["ok"])
        self.assertIn("utr-core-01", [d["name"] for d in inv["devices"]])
        self.assertIn("utrecht", [s["site"] for s in inv["sites"]])

    def test_validate(self):
        status, _, body = self.request("POST", "/api/validate", {})
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertTrue(result["ok"], result["errors"])
        self.assertIn("No problems found", result["summary"])

    def test_plan_from_nothing_adds_everything(self):
        status, _, body = self.request("POST", "/api/plan", {"base": ""})
        self.assertEqual(status, 200)
        plan = json.loads(body)
        self.assertTrue(plan["ok"], plan.get("errors"))
        self.assertIn("utr-core-01", plan["devices"])
        self.assertTrue(plan["devices"]["utr-core-01"]["commands"])

    def test_plan_refuses_option_like_refs(self):
        status, _, body = self.request("POST", "/api/plan", {"base": "--output=/tmp/x"})
        self.assertEqual(status, 400)
        self.assertFalse(json.loads(body)["ok"])

    def test_post_needs_json(self):
        status, _, _ = self.request("POST", "/api/validate", {}, headers={"Content-Type": "text/plain"})
        self.assertEqual(status, 415)

    def test_host_check(self):
        self.assertTrue(_host_is_local("127.0.0.1:8765"))
        self.assertTrue(_host_is_local("localhost"))
        self.assertTrue(_host_is_local("[::1]:8765"))
        self.assertFalse(_host_is_local("127.0.0.1.evil.example"))
        self.assertFalse(_host_is_local(None))


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


if __name__ == "__main__":
    unittest.main()
