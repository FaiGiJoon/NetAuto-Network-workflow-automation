"""Tests for validate.py and plan.py. Run with:  python -m unittest discover -s tests"""

import copy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from netlib import desired_state, load_from_disk  # noqa: E402
from plan import build_plan  # noqa: E402
from validate import validate  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
BASE = load_from_disk(REPO)


def with_vlan(**overrides):
    """Copy of the real data with one extra VLAN at Utrecht."""
    data = copy.deepcopy(BASE)
    vlan = {"id": 30, "name": "utr-office", "subnet": "10.10.30.0/24",
            "gateway": "10.10.30.1", "gateway_device": "utr-core-01",
            "devices": ["utr-core-01", "utr-sw-01"]}
    vlan.update(overrides)
    vlan = {k: v for k, v in vlan.items() if v is not None}
    data["sites"]["data/sites/utrecht.yml"]["vlans"].append(vlan)
    return data


class ValidateTests(unittest.TestCase):
    def assertError(self, data, text):
        errors = validate(data)
        self.assertTrue(any(text in e for e in errors), f"expected '{text}' in {errors}")

    def test_repo_data_is_valid(self):
        self.assertEqual(validate(BASE), [])

    def test_good_new_vlan(self):
        self.assertEqual(validate(with_vlan()), [])

    def test_duplicate_id(self):
        self.assertError(with_vlan(id=20), "already used")

    def test_reserved_id(self):
        self.assertError(with_vlan(id=1002), "reserved")

    def test_id_out_of_range(self):
        self.assertError(with_vlan(id=5000), "2 to 4094")

    def test_name_without_site_code(self):
        self.assertError(with_vlan(name="office"), "site code")

    def test_name_with_uppercase(self):
        self.assertError(with_vlan(name="utr-Office"), "lowercase")

    def test_overlapping_subnet(self):
        self.assertError(with_vlan(subnet="10.10.20.128/25", gateway="10.10.20.129"), "overlaps")

    def test_host_bits_set(self):
        self.assertError(with_vlan(subnet="10.10.30.5/24"), "host bits")

    def test_gateway_outside_subnet(self):
        self.assertError(with_vlan(gateway="10.10.99.1"), "usable address")

    def test_gateway_is_network_address(self):
        self.assertError(with_vlan(gateway="10.10.30.0"), "usable address")

    def test_unknown_device(self):
        self.assertError(with_vlan(devices=["utr-core-01", "utr-sw-99"]), "not in data/devices.yml")

    def test_device_from_other_site(self):
        self.assertError(with_vlan(devices=["utr-core-01", "ams-core-01"]), "belongs to site")

    def test_gateway_on_layer2_switch(self):
        self.assertError(with_vlan(gateway_device="utr-sw-01"), "not a layer-3")

    def test_dhcp_includes_gateway(self):
        self.assertError(with_vlan(dhcp={"start": "10.10.30.1", "end": "10.10.30.50"}), "gateway")

    def test_dhcp_outside_subnet(self):
        self.assertError(with_vlan(dhcp={"start": "10.10.30.10", "end": "10.10.31.5"}), "inside")

    def test_typo_in_field(self):
        self.assertError(with_vlan(gatway="10.10.30.1"), "unknown field 'gatway'")

    def test_command_injection_in_description(self):
        self.assertError(with_vlan(description='x"] ; /system reset-configuration'), "not allowed")


class PlanTests(unittest.TestCase):
    """Builds a throwaway Git repo, commits changes, and plans between them."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        subprocess.run(["cp", "-r", str(REPO / "data"), str(self.root / "data")], check=True)
        self.git("init", "-q", "-b", "main")
        self.commit("initial")
        self.first = self.head()

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        return subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
                              cwd=self.root, check=True, capture_output=True, text=True).stdout

    def head(self):
        return self.git("rev-parse", "HEAD").strip()

    def commit(self, msg):
        self.git("add", "-A")
        self.git("commit", "-qm", msg, "--allow-empty")

    def edit_site(self, fn):
        path = self.root / "data/sites/utrecht.yml"
        site = yaml.safe_load(path.read_text())
        fn(site)
        path.write_text(yaml.safe_dump(site, sort_keys=False))

    def test_no_change(self):
        plan = build_plan(self.first, None, self.root)
        self.assertEqual(plan["devices"], {})

    def test_from_empty_adds_everything(self):
        plan = build_plan(None, None, self.root)
        self.assertEqual(len(plan["devices"]["utr-core-01"]["add"]), 2)

    def test_add_vlan(self):
        self.edit_site(lambda s: s["vlans"].append(
            {"id": 30, "name": "utr-office", "subnet": "10.10.30.0/24",
             "devices": ["utr-sw-01"]}))
        plan = build_plan(self.first, None, self.root)
        self.assertEqual(list(plan["devices"]), ["utr-sw-01"])
        cfg = "\n".join(plan["devices"]["utr-sw-01"]["commands"])
        self.assertIn("vlan 30\n name utr-office", cfg)
        self.assertNotIn("interface Vlan30", cfg)   # layer 2 only

    def test_change_and_rollback(self):
        self.edit_site(lambda s: s["vlans"][1].update(name="utr-cams"))
        self.commit("rename")
        changed = self.head()
        plan = build_plan(self.first, changed, self.root)
        ros = "\n".join(plan["devices"]["utr-core-01"]["commands"])
        self.assertIn('set [find where comment="netauto:vlan20"] name="utr-cams"', ros)
        ios = "\n".join(plan["devices"]["utr-sw-01"]["commands"])
        self.assertIn(" name utr-cams", ios)
        # Rollback = plan from the changed commit back to the first one.
        back = build_plan(changed, self.first, self.root)
        ros_back = "\n".join(back["devices"]["utr-core-01"]["commands"])
        self.assertIn('name="utr-cameras"', ros_back)

    def test_remove_vlan(self):
        self.edit_site(lambda s: s["vlans"].pop(1))
        plan = build_plan(self.first, None, self.root)
        ros = plan["devices"]["utr-core-01"]["commands"]
        self.assertEqual(ros[-1], '/interface vlan remove [find where comment="netauto:vlan20"]')
        self.assertTrue(ros[0].startswith("/ip dhcp-server remove"))  # dhcp first, vlan last
        ios = plan["devices"]["utr-sw-01"]["commands"]
        self.assertEqual(ios[-1], "no vlan 20")
        self.assertEqual(plan["devices"]["utr-sw-01"]["verify_absent"], [20])

    def test_dhcp_change_on_ios_removes_old_exclusions(self):
        path = self.root / "data/sites/amsterdam.yml"
        site = yaml.safe_load(path.read_text())
        site["vlans"][0]["dhcp"] = {"start": "10.20.10.50", "end": "10.20.10.99"}
        path.write_text(yaml.safe_dump(site, sort_keys=False))
        self.commit("dhcp")
        with_dhcp = self.head()
        site["vlans"][0]["dhcp"] = {"start": "10.20.10.100", "end": "10.20.10.150"}
        path.write_text(yaml.safe_dump(site, sort_keys=False))
        plan = build_plan(with_dhcp, None, self.root)
        cfg = plan["devices"]["ams-core-01"]["commands"]
        self.assertIn("no ip dhcp excluded-address 10.20.10.1 10.20.10.49", cfg)
        self.assertIn("ip dhcp excluded-address 10.20.10.1 10.20.10.99", cfg)

    def test_invalid_target_is_refused(self):
        self.edit_site(lambda s: s["vlans"][1].update(id=10))
        with self.assertRaises(Exception) as ctx:
            build_plan(self.first, None, self.root)
        self.assertIn("already used", str(ctx.exception))


class StateTests(unittest.TestCase):
    def test_gateway_only_on_gateway_device(self):
        state = desired_state(BASE)
        self.assertIsNotNone(state["utr-core-01"]["vlans"][20]["l3"])
        self.assertIsNone(state["utr-sw-01"]["vlans"][20]["l3"])


if __name__ == "__main__":
    unittest.main()
