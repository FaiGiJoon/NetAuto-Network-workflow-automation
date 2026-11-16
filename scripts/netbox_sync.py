#!/usr/bin/env python3
"""Keep NetBox up to date with what is in Git: VLANs, prefixes and gateway IPs.

Git stays the source of truth. This script only creates and updates; it never
deletes. VLANs that are in NetBox but not in Git are listed as warnings so a
person can decide. Sites must already exist in NetBox (slug = site name).

Env: NETBOX_URL (e.g. https://netbox.internal), NETBOX_TOKEN.
"""

from __future__ import annotations

import ipaddress
import os
import sys
import urllib.parse

from httpjson import request
from netlib import load_from_disk

TAG_NOTE = "managed by netauto"


def main() -> int:
    url = os.environ.get("NETBOX_URL", "").rstrip("/")
    token = os.environ.get("NETBOX_TOKEN", "")
    if not url or not token:
        print("NETBOX_URL / NETBOX_TOKEN not set: skipping the NetBox sync.")
        return 0
    api, headers = f"{url}/api", {"Authorization": f"Token {token}"}

    def get(path, **params):
        query = urllib.parse.urlencode(params)
        return request("GET", f"{api}{path}?{query}", headers)["results"]

    def upsert(path, existing, body, label):
        if existing:
            obj = existing[0]
            changes = {k: v for k, v in body.items() if _value(obj.get(k)) != v}
            if changes:
                request("PATCH", f"{api}{path}{obj['id']}/", headers, changes)
                print(f"updated {label}: {sorted(changes)}")
            return obj["id"]
        created = request("POST", f"{api}{path}", headers, body)
        print(f"created {label}")
        return created["id"]

    data = load_from_disk()
    problems = 0
    for site in data["sites"].values():
        found = get("/dcim/sites/", slug=site["site"])
        if not found:
            print(f"WARNING site '{site['site']}' is not in NetBox: create it first (slug '{site['site']}')")
            problems += 1
            continue
        site_id = found[0]["id"]
        in_git = set()
        for vlan in site.get("vlans") or []:
            in_git.add(vlan["id"])
            desc = f"{vlan.get('description', '')} ({TAG_NOTE})".strip()
            vlan_id = upsert("/ipam/vlans/", get("/ipam/vlans/", site_id=site_id, vid=vlan["id"]),
                             {"site": site_id, "vid": vlan["id"], "name": vlan["name"],
                              "status": "active", "description": desc},
                             f"VLAN {vlan['id']} {vlan['name']}")
            upsert("/ipam/prefixes/", get("/ipam/prefixes/", prefix=vlan["subnet"]),
                   {"prefix": vlan["subnet"], "vlan": vlan_id, "status": "active", "description": desc},
                   f"prefix {vlan['subnet']}")
            if vlan.get("gateway"):
                plen = ipaddress.ip_network(vlan["subnet"]).prefixlen
                addr = f"{vlan['gateway']}/{plen}"
                upsert("/ipam/ip-addresses/", get("/ipam/ip-addresses/", address=addr),
                       {"address": addr, "status": "active",
                        "description": f"gateway {vlan['name']} ({TAG_NOTE})"},
                       f"gateway {addr}")
        for extra in get("/ipam/vlans/", site_id=site_id, limit=1000):
            if extra["vid"] not in in_git:
                print(f"WARNING VLAN {extra['vid']} '{extra['name']}' at {site['site']} is in NetBox but not in Git")
    return 1 if problems else 0


def _value(v):
    """NetBox returns nested objects ({'id': 3, ...}) and choices ({'value': 'active'})."""
    if isinstance(v, dict):
        return v.get("id", v.get("value"))
    return v


if __name__ == "__main__":
    sys.exit(main())
