#!/usr/bin/env python3
"""Ansible dynamic inventory built from data/devices.yml.

Groups: one per platform (routeros, ios) and one per site (site_utrecht, ...).
"""

import json
import sys
from pathlib import Path

import yaml

DATA = Path(__file__).resolve().parent.parent / "data" / "devices.yml"
NETWORK_OS = {"routeros": "community.routeros.routeros", "ios": "cisco.ios.ios"}


def build() -> dict:
    devices = (yaml.safe_load(DATA.read_text(encoding="utf-8")) or {}).get("devices") or []
    inv: dict = {"_meta": {"hostvars": {}}, "all": {"children": []}}
    for dev in devices:
        name, platform = dev["name"], dev["platform"]
        inv["_meta"]["hostvars"][name] = {
            "ansible_host": dev["mgmt_ip"],
            "ansible_network_os": NETWORK_OS[platform],
            "netauto_platform": platform,
            "netauto_site": dev["site"],
        }
        for group in (platform, f"site_{dev['site']}"):
            inv.setdefault(group, {"hosts": []})["hosts"].append(name)
            if group not in inv["all"]["children"]:
                inv["all"]["children"].append(group)
    return inv


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--host":
        print(json.dumps({}))
    else:
        print(json.dumps(build(), indent=2))
