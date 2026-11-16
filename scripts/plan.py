#!/usr/bin/env python3
"""Compare two versions of the network data and write out exactly what will
change on each device, plus the commands to do it.

    python scripts/plan.py --base <old commit> [--target <new commit>] [--out build]

--base    the commit that is currently on the devices (the last deployed one)
--target  the commit you want on the devices; default = the files on disk
          (for a rollback: --target is the older, good commit)

Writes:
  build/plan.json             machine-readable plan, read by Ansible
  build/plan.md               human-readable plan, for the merge request review
  build/commands/<dev>.rsc    RouterOS commands per device
  build/commands/<dev>.cfg    Cisco IOS config per device
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path

from netlib import REPO_ROOT, DataError, desired_state, load_from_disk, load_from_git, ref_exists
from validate import validate


# ------------------------------------------------------------------ diff

def diff_states(old: dict, new: dict) -> tuple[dict, list[str]]:
    plan, warnings = {}, []
    for dev in sorted(set(old) - set(new)):
        warnings.append(f"{dev} was removed from devices.yml: it is NOT touched. "
                        "Remove its VLANs first if they must go.")
    for dev, wanted in sorted(new.items()):
        before = old.get(dev)
        if before and before["meta"]["platform"] != wanted["meta"]["platform"]:
            warnings.append(f"{dev}: platform changed, treating it as a new device")
            before = None
        old_vlans = before["vlans"] if before else {}
        new_vlans = wanted["vlans"]
        add = [new_vlans[v] for v in sorted(set(new_vlans) - set(old_vlans))]
        remove = [old_vlans[v] for v in sorted(set(old_vlans) - set(new_vlans))]
        change = [
            {"old": old_vlans[v], "new": new_vlans[v]}
            for v in sorted(set(new_vlans) & set(old_vlans))
            if old_vlans[v] != new_vlans[v]
        ]
        if before and before["meta"]["trunk_ports"] != wanted["meta"]["trunk_ports"]:
            # Trunk ports changed: re-apply every VLAN so the trunks are right.
            touched = {c["new"]["id"] for c in change} | {a["id"] for a in add}
            change += [{"old": old_vlans[v], "new": new_vlans[v]}
                       for v in sorted(set(new_vlans) & set(old_vlans)) if v not in touched]
        if add or remove or change:
            plan[dev] = {"meta": wanted["meta"], "old_meta": before["meta"] if before else None,
                         "add": add, "change": change, "remove": remove}
    return plan, warnings


# -------------------------------------------------------------- RouterOS

def _ros_upsert(menu: str, tag: str, add_args: str, set_args: str) -> str:
    return (f':if ([:len [{menu} find where comment="{tag}"]] = 0) '
            f'do={{{menu} add {add_args} comment="{tag}"}} '
            f'else={{{menu} set [find where comment="{tag}"] {set_args}}}')


def _ros_remove(menu: str, tag: str) -> str:
    return f'{menu} remove [find where comment="{tag}"]'


def ros_apply(vlan: dict, meta: dict) -> list[str]:
    tag, vid, name, bridge = f"netauto:vlan{vlan['id']}", vlan["id"], vlan["name"], meta["bridge"]
    tagged = ",".join([bridge, *meta["trunk_ports"]])
    cmds = [
        _ros_upsert("/interface vlan", tag,
                    f'name="{name}" vlan-id={vid} interface={bridge}',
                    f'name="{name}" vlan-id={vid} interface={bridge}'),
        _ros_upsert("/interface bridge vlan", tag,
                    f"bridge={bridge} vlan-ids={vid} tagged={tagged}",
                    f"vlan-ids={vid} tagged={tagged}"),
    ]
    l3, dhcp = vlan["l3"], vlan["dhcp"]
    if l3:
        addr = f"{l3['gateway']}/{l3['prefixlen']}"
        cmds.append(_ros_upsert("/ip address", tag,
                                f'address={addr} interface="{name}"',
                                f'address={addr} interface="{name}"'))
    if dhcp:
        pool = f"dhcp-{name}"
        cmds += [
            _ros_upsert("/ip pool", tag,
                        f'name="{pool}" ranges={dhcp["start"]}-{dhcp["end"]}',
                        f'name="{pool}" ranges={dhcp["start"]}-{dhcp["end"]}'),
            _ros_upsert("/ip dhcp-server network", tag,
                        f"address={l3['subnet']} gateway={l3['gateway']} dns-server={l3['gateway']}",
                        f"address={l3['subnet']} gateway={l3['gateway']} dns-server={l3['gateway']}"),
            _ros_upsert("/ip dhcp-server", tag,
                        f'name="{pool}" interface="{name}" address-pool="{pool}" disabled=no',
                        f'name="{pool}" interface="{name}" address-pool="{pool}" disabled=no'),
        ]
    else:
        cmds += [_ros_remove("/ip dhcp-server", tag),
                 _ros_remove("/ip dhcp-server network", tag),
                 _ros_remove("/ip pool", tag)]
    if not l3:
        cmds.append(_ros_remove("/ip address", tag))
    return cmds


def ros_remove(vlan: dict) -> list[str]:
    tag = f"netauto:vlan{vlan['id']}"
    return [_ros_remove(m, tag) for m in (
        "/ip dhcp-server", "/ip dhcp-server network", "/ip pool",
        "/ip address", "/interface bridge vlan", "/interface vlan")]


def render_routeros(entry: dict) -> list[str]:
    meta = entry["meta"]
    cmds: list[str] = []
    for v in entry["remove"]:
        cmds += ros_remove(v)
    for c in entry["change"]:
        cmds += ros_apply(c["new"], meta)
    for v in entry["add"]:
        cmds += ros_apply(v, meta)
    return cmds


# ------------------------------------------------------------- Cisco IOS

def _excluded_ranges(l3: dict, dhcp: dict) -> list[tuple[str, str]]:
    net = ipaddress.ip_network(l3["subnet"])
    first, last = net.network_address + 1, net.broadcast_address - 1
    start, end = ipaddress.ip_address(dhcp["start"]), ipaddress.ip_address(dhcp["end"])
    ranges = []
    if start > first:
        ranges.append((str(first), str(start - 1)))
    if end < last:
        ranges.append((str(end + 1), str(last)))
    return ranges


def ios_dhcp_remove(vlan: dict) -> list[str]:
    lines = [f"no ip dhcp pool {vlan['name']}"]
    lines += [f"no ip dhcp excluded-address {a} {b}"
              for a, b in _excluded_ranges(vlan["l3"], vlan["dhcp"])]
    return lines


def ios_apply(vlan: dict, meta: dict, old: dict | None = None) -> list[str]:
    vid, name = vlan["id"], vlan["name"]
    lines = []
    if old and old["dhcp"] and (old["dhcp"] != vlan["dhcp"] or old["name"] != name
                                or old["l3"] != vlan["l3"]):
        lines += ios_dhcp_remove(old)
    if old and old["l3"] and not vlan["l3"]:
        lines.append(f"no interface Vlan{vid}")
    lines += [f"vlan {vid}", f" name {name}"]
    if vlan["l3"]:
        l3 = vlan["l3"]
        lines += [f"interface Vlan{vid}",
                  f" description {vlan['description'] or name}",
                  f" ip address {l3['gateway']} {l3['netmask']}",
                  " no shutdown"]
    for port in meta["trunk_ports"]:
        lines += [f"interface {port}", f" switchport trunk allowed vlan add {vid}"]
    if vlan["dhcp"]:
        l3, net = vlan["l3"], ipaddress.ip_network(vlan["l3"]["subnet"])
        lines += [f"ip dhcp excluded-address {a} {b}" for a, b in _excluded_ranges(l3, vlan["dhcp"])]
        lines += [f"ip dhcp pool {name}",
                  f" network {net.network_address} {net.netmask}",
                  f" default-router {l3['gateway']}",
                  f" dns-server {l3['gateway']}"]
    return lines


def ios_remove(vlan: dict, meta: dict) -> list[str]:
    vid = vlan["id"]
    lines = ios_dhcp_remove(vlan) if vlan["dhcp"] else []
    if vlan["l3"]:
        lines.append(f"no interface Vlan{vid}")
    for port in meta["trunk_ports"]:
        lines += [f"interface {port}", f" switchport trunk allowed vlan remove {vid}"]
    lines.append(f"no vlan {vid}")
    return lines


def render_ios(entry: dict) -> list[str]:
    meta = entry["meta"]
    old_meta = entry["old_meta"] or meta
    lines = []
    for v in entry["remove"]:
        lines += ios_remove(v, old_meta)
    for port in sorted(set(old_meta["trunk_ports"]) - set(meta["trunk_ports"])):
        for c in entry["change"]:
            lines += [f"interface {port}", f" switchport trunk allowed vlan remove {c['new']['id']}"]
    for c in entry["change"]:
        lines += ios_apply(c["new"], meta, c["old"])
    for v in entry["add"]:
        lines += ios_apply(v, meta)
    return lines


# ------------------------------------------------------------------ main

def describe(v: dict) -> str:
    extra = []
    if v["l3"]:
        extra.append(f"gateway {v['l3']['gateway']}/{v['l3']['prefixlen']}")
    if v["dhcp"]:
        extra.append(f"DHCP {v['dhcp']['start']}-{v['dhcp']['end']}")
    return f"VLAN {v['id']} `{v['name']}`" + (f" ({', '.join(extra)})" if extra else "")


def build_plan(base: str | None, target: str | None, root: Path = REPO_ROOT) -> dict:
    old_data = load_from_git(base, root)
    new_data = load_from_disk(root) if target is None else load_from_git(target, root)
    if target is not None and not ref_exists(target, root):
        raise DataError([f"target commit '{target}' does not exist"])
    errors = validate(new_data)
    if errors:
        raise DataError(["target data is not valid:"] + errors)
    plan, warnings = diff_states(desired_state(old_data), desired_state(new_data))
    devices = {}
    for dev, entry in plan.items():
        platform = entry["meta"]["platform"]
        commands = render_routeros(entry) if platform == "routeros" else render_ios(entry)
        devices[dev] = {
            "platform": platform,
            "mgmt_ip": entry["meta"]["mgmt_ip"],
            "add": entry["add"], "change": entry["change"], "remove": entry["remove"],
            "commands": commands,
            "verify_present": [v["name"] for v in entry["add"]] + [c["new"]["name"] for c in entry["change"]],
            "verify_absent": [v["id"] for v in entry["remove"]],
        }
    return {"base": base, "target": target or "working tree",
            "warnings": warnings, "devices": devices}


def write_outputs(plan: dict, out: Path) -> None:
    (out / "commands").mkdir(parents=True, exist_ok=True)
    for old in (out / "commands").iterdir():
        old.unlink()
    (out / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
    md = [f"# Network change plan", "",
          f"From `{plan['base'] or 'nothing'}` to `{plan['target']}`", ""]
    for w in plan["warnings"]:
        md.append(f"> WARNING: {w}")
    if not plan["devices"]:
        md.append("No changes. Nothing will be pushed.")
    for dev, d in plan["devices"].items():
        md += [f"## {dev} ({d['platform']}, {d['mgmt_ip']})", ""]
        md += [f"- ADD {describe(v)}" for v in d["add"]]
        md += [f"- CHANGE {describe(c['old'])} -> {describe(c['new'])}" for c in d["change"]]
        md += [f"- REMOVE {describe(v)}" for v in d["remove"]]
        ext = "rsc" if d["platform"] == "routeros" else "cfg"
        text = "\n".join(d["commands"]) + "\n"
        (out / "commands" / f"{dev}.{ext}").write_text(text, encoding="utf-8")
        md += ["", "```", text.rstrip(), "```", ""]
    (out / "plan.md").write_text("\n".join(md) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", help="commit currently on the devices")
    ap.add_argument("--target", help="commit to deploy (default: files on disk)")
    ap.add_argument("--out", default=str(REPO_ROOT / "build"))
    args = ap.parse_args()
    try:
        plan = build_plan(args.base, args.target)
    except DataError as exc:
        for e in exc.errors:
            print(f"ERROR {e}")
        return 1
    write_outputs(plan, Path(args.out))
    print(Path(args.out, "plan.md").read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
