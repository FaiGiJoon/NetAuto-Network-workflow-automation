"""End-to-end tests for the single-file programs in apps/. Builds the .pyz
versions, then runs each program's setup and commands as a user would,
against the fake services from test_workflows.py. Nothing is installed.

Run with:  python -m unittest discover -s tests
"""

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import build_executables  # noqa: E402
from test_workflows import WithServer  # noqa: E402

DIST = Path(tempfile.mkdtemp(prefix="netops-dist-"))
_built = False


def build_once():
    global _built
    if not _built:
        build_executables.build_pyz(DIST)
        _built = True


class AppTests(WithServer):
    def setUp(self):
        super().setUp()
        build_once()
        self.work = Path(self.tmp.name)
        self.appenv = {**os.environ,
                    "HOME": str(self.work), "NETOPS_CONFIG": str(self.work / "netops.env"),
                    "NETOPS_STATE_DIR": str(self.work / "state"), "PYTHONDONTWRITEBYTECODE": "1"}

    def run_app(self, app, *args, ok=True, env=None):
        r = subprocess.run([sys.executable, str(DIST / f"{app}.pyz"), *args], capture_output=True, text=True,
                           env={**self.appenv, **(env or {})}, cwd=self.work, stdin=subprocess.DEVNULL, timeout=120)
        if ok and r.returncode != 0:
            self.fail(f"{app} {' '.join(args)} failed ({r.returncode}):\n{r.stdout}\n{r.stderr}")
        return r

    def config(self):
        lines = (self.work / "netops.env").read_text().splitlines()
        return dict(l.split("=", 1) for l in lines if "=" in l and not l.startswith("#"))

    # ------------------------------------------------------------------ netauto
    def test_netauto_init_validate_plan(self):
        repo = self.work / "repo"
        r = self.run_app("netauto", "init", str(repo))
        self.assertIn("No problems found", r.stdout)
        for f in ("data/devices.yml", ".gitlab-ci.yml", "scripts/plan.py", "ansible/deploy.yml"):
            self.assertTrue((repo / f).exists(), f)
        r = self.run_app("netauto", "plan", "--repo", str(repo))
        self.assertIn("## utr-core-01", r.stdout)
        self.assertTrue((repo / "build/commands/utr-sw-01.cfg").exists())
        site = repo / "data/sites/utrecht.yml"
        site.write_text(site.read_text().replace("id: 20", "id: 10"))
        r = self.run_app("netauto", "validate", "--repo", str(repo), ok=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn("already used", r.stdout)

    # ---------------------------------------------------------------- netops-ids
    def test_ids_setup_check_and_run(self):
        eve = self.work / "eve.json"
        eve.write_text("".join(json.dumps({"event_type": "alert", "src_ip": "198.51.100.20", "dest_ip": "10.0.0.5",
                                           "alert": {"signature": f"ET SCAN {i}", "severity": 3}}) + "\n" for i in range(5)))
        r = self.run_app("netops-ids", "setup", "--yes", "--no-service",
                         env={"IDS_ALERT_FILE": str(eve), "NETOPS_DRY_RUN": "false"})
        self.assertIn("MikroTik 127.0.0.1: hEX, RouterOS 7.16", r.stdout)
        self.assertIn("drop rule added", r.stdout)
        self.assertEqual(self.fake.raw_rules[0]["src-address-list"], "netops-blocked")
        cfg = self.config()
        self.assertEqual(cfg["IDS_ALERT_FILE"], str(eve))
        self.assertEqual(stat.S_IMODE((self.work / "netops.env").stat().st_mode), 0o600)
        # Setup again: the rule is not added twice.
        r = self.run_app("netops-ids", "setup", "--yes", "--no-service")
        self.assertIn("drop rule exists", r.stdout)
        self.run_app("netops-ids", "check")
        self.run_app("netops-ids", "run", "--from-start", "--once")
        self.assertEqual([x["address"] for x in self.fake.address_list], ["198.51.100.20"])
        self.run_app("netops-ids", "poe-restart", "--device", "cam-1", "--switch", "127.0.0.1", "--port", "ether7")
        self.assertEqual(self.fake.poe_cycles, [{"numbers": "ether7", "duration": "5s"}])

    def test_ids_setup_without_router_settings_fails_clearly(self):
        env = {k: "" for k in ("MIKROTIK_HOST", "MIKROTIK_USER", "MIKROTIK_PASSWORD")}
        r = self.run_app("netops-ids", "setup", "--yes", "--no-service", ok=False, env=env)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Missing MIKROTIK_HOST", r.stdout + r.stderr)

    # ----------------------------------------------------------- netops-crowdsec
    def test_crowdsec_setup_syncs(self):
        self.fake.crowdsec = {"new": [{"value": "203.0.113.9", "scope": "Ip", "origin": "crowdsec", "type": "ban",
                                       "duration": "4h", "scenario": "ssh-bf"}], "deleted": []}
        r = self.run_app("netops-crowdsec", "setup", "--yes", "--no-service", env={"NETOPS_DRY_RUN": "false"})
        self.assertIn("CrowdSec Local API reachable", r.stdout)
        self.assertEqual([x["address"] for x in self.fake.address_list], ["203.0.113.9"])
        self.assertEqual(self.fake.raw_rules[0]["src-address-list"], "crowdsec-blocked")

    # ---------------------------------------------------------------- netops-soc
    def test_soc_test_check_and_wazuh_call(self):
        r = self.run_app("netops-soc", "test")
        self.assertIn("203.0.113.7", r.stdout)
        self.assertEqual(self.fake.opnsense, [])                  # dry run
        self.run_app("netops-soc", "setup", "--yes", "--no-service", env={"NETOPS_DRY_RUN": "false"})
        self.fake.abuse_score = 95
        alert = self.work / "alert.json"
        alert.write_text(json.dumps({"rule": {"level": 12, "description": "x"}, "data": {"src_ip": "203.0.113.7"}}))
        self.run_app("netops-soc", str(alert), "api-key", "hook-url")   # exactly how Wazuh calls it
        self.assertEqual(self.fake.opnsense, [("netops_blocked", "203.0.113.7")])

    # ------------------------------------------------------------ netops-metrics
    def test_metrics_setup_writes_a_stack(self):
        stack = self.work / "metrics"
        devices = Path(__file__).resolve().parent.parent / "data/devices.yml"
        self.run_app("netops-metrics", "setup", "--yes", "--no-start",
                     env={"NETOPS_METRICS_DIR": str(stack), "NETOPS_DEVICES_FILE": str(devices)})
        compose = yaml.safe_load((stack / "docker-compose.yml").read_text())
        self.assertIn("./remediation/workflows:/app:ro", compose["services"]["remediation"]["volumes"])
        self.assertTrue((stack / "remediation/workflows/3-prometheus-grafana/remediation_receiver.py").exists())
        self.assertTrue((stack / "remediation/workflows/common/netops/actions.py").exists())
        snmp = yaml.safe_load((stack / "prometheus/targets/snmp.yml").read_text())
        self.assertEqual(len(snmp), 3)
        am = yaml.safe_load((stack / "alertmanager/alertmanager.yml").read_text())
        token = am["receivers"][0]["webhook_configs"][0]["http_config"]["authorization"]["credentials"]
        self.assertIn(f"REMEDIATION_TOKEN={token}", (stack / ".env").read_text())
        self.assertEqual(stat.S_IMODE((stack / ".env").stat().st_mode), 0o600)
        prom = yaml.safe_load((stack / "prometheus/prometheus.yml").read_text())
        self.assertEqual(next(j for j in prom["scrape_configs"] if j["job_name"] == "snmp")["params"]["auth"], ["netops"])

    # ------------------------------------------------------------ netops-homelab
    def test_homelab_setup_fills_the_n8n_workflow(self):
        stack = self.work / "homelab"
        ports = {"cam-1": {"switch": "10.255.10.1", "port": "ether7"}}
        self.run_app("netops-homelab", "setup", "--yes", "--no-start",
                     env={"HOMELAB_DIR": str(stack), "HOMELAB_POE_PORTS": json.dumps(ports)})
        wf = json.loads((stack / "n8n-poe-restart-workflow.json").read_text())
        code = next(n for n in wf["nodes"] if n["type"] == "n8n-nodes-base.code")["parameters"]["jsCode"]
        self.assertIn('"cam-1"', code)
        self.assertNotIn("cam-utr-11", code)
        self.assertIn("MIKROTIK_BASIC_AUTH=", (stack / ".env").read_text())


if __name__ == "__main__":
    unittest.main()
