#!/usr/bin/env python3
"""Check the network data before anything touches a device.

Checks: YAML syntax, unknown/missing fields, naming rules, VLAN ID ranges,
duplicate IDs and names, overlapping subnets, gateway and DHCP ranges,
device references, and characters that could break device commands.

Exit code 0 = all good, 1 = errors found (CI job fails).
"""

from __future__ import annotations

import ipaddress
import re
import sys

from netlib import DataError, load_from_disk

NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
SITE_CODE_RE = re.compile(r"^[a-z]{2,5}$")
DEVICE_NAME_RE = re.compile(r"^[a-z]{2,5}-[a-z0-9]+-\d{2}$")
# Characters that could break out of a quoted RouterOS/IOS argument.
UNSAFE_CHARS = set('"\'`;$[]{}\\\n\r')

PLATFORMS = {"routeros", "ios"}
RESERVED_VLANS = {1, 1002, 1003, 1004, 1005}  # default + Cisco reserved
DEVICE_KEYS = {"name", "site", "platform", "mgmt_ip", "l3", "bridge", "trunk_ports"}
DEVICE_REQUIRED = {"name", "site", "platform", "mgmt_ip"}
SITE_KEYS = {"site", "code", "vlans"}
VLAN_KEYS = {"id", "name", "description", "subnet", "gateway", "gateway_device",
             "devices", "dhcp"}
VLAN_REQUIRED = {"id", "name", "subnet", "devices"}


def validate(data: dict) -> list[str]:
    errors: list[str] = []
    err = errors.append

    # ------------------------------------------------------------ sites
    sites_by_name: dict[str, dict] = {}
    for path, site in data["sites"].items():
        if not isinstance(site, dict):
            err(f"{path}: must be a mapping with site, code and vlans")
            continue
        for key in sorted(set(site) - SITE_KEYS):
            err(f"{path}: unknown field '{key}'")
        name, code = site.get("site"), site.get("code")
        if not name:
            err(f"{path}: missing 'site'")
            continue
        stem = path.rsplit("/", 1)[-1].removesuffix(".yml")
        if name != stem:
            err(f"{path}: site '{name}' must match the file name '{stem}'")
        if not isinstance(code, str) or not SITE_CODE_RE.match(code):
            err(f"{path}: 'code' must be 2-5 lowercase letters")
        if name in sites_by_name:
            err(f"{path}: site '{name}' is defined twice")
        sites_by_name[name] = site
    codes = [s.get("code") for s in sites_by_name.values()]
    for code in {c for c in codes if codes.count(c) > 1}:
        err(f"site code '{code}' is used by more than one site")

    # ---------------------------------------------------------- devices
    devices: dict[str, dict] = {}
    mgmt_ips: dict[str, str] = {}
    for i, dev in enumerate(data["devices"]):
        where = f"data/devices.yml: devices[{i}]"
        if not isinstance(dev, dict):
            err(f"{where}: must be a mapping")
            continue
        where += f" ({dev.get('name', '?')})"
        for key in sorted(set(dev) - DEVICE_KEYS):
            err(f"{where}: unknown field '{key}'")
        for key in sorted(DEVICE_REQUIRED - set(dev)):
            err(f"{where}: missing '{key}'")
        name = dev.get("name")
        if not name:
            continue
        if not DEVICE_NAME_RE.match(str(name)):
            err(f"{where}: name must look like <sitecode>-<role>-<nn>, e.g. utr-core-01")
        if name in devices:
            err(f"{where}: device name '{name}' is used twice")
        devices[name] = dev
        site = sites_by_name.get(dev.get("site"))
        if site is None:
            err(f"{where}: site '{dev.get('site')}' has no file in data/sites/")
        elif not str(name).startswith(f"{site.get('code')}-"):
            err(f"{where}: name must start with the site code '{site.get('code')}-'")
        if dev.get("platform") not in PLATFORMS:
            err(f"{where}: platform must be one of {sorted(PLATFORMS)}")
        if dev.get("platform") == "routeros" and not dev.get("bridge"):
            err(f"{where}: RouterOS devices need 'bridge'")
        try:
            ip = str(ipaddress.ip_address(dev.get("mgmt_ip")))
            if ip in mgmt_ips:
                err(f"{where}: mgmt_ip {ip} is also used by {mgmt_ips[ip]}")
            mgmt_ips[ip] = name
        except ValueError:
            err(f"{where}: mgmt_ip '{dev.get('mgmt_ip')}' is not a valid IP address")
        ports = dev.get("trunk_ports", [])
        if not isinstance(ports, list):
            err(f"{where}: trunk_ports must be a list")
        else:
            for port in ports:
                _check_safe(err, where, "trunk port", port)
        _check_safe(err, where, "bridge", dev.get("bridge"))

    # ------------------------------------------------------------ vlans
    vlan_names: dict[str, str] = {}
    gateways: dict[str, str] = {}
    subnets: list[tuple[ipaddress.IPv4Network, str]] = []

    for path, site in data["sites"].items():
        if not isinstance(site, dict):
            continue
        site_name, code = site.get("site"), site.get("code")
        vlans = site.get("vlans") or []
        if not isinstance(vlans, list):
            err(f"{path}: 'vlans' must be a list")
            continue
        ids_here: dict[int, str] = {}
        for i, vlan in enumerate(vlans):
            where = f"{path}: vlans[{i}]"
            if not isinstance(vlan, dict):
                err(f"{where}: must be a mapping")
                continue
            where += f" ({vlan.get('name', '?')})"
            for key in sorted(set(vlan) - VLAN_KEYS):
                err(f"{where}: unknown field '{key}'")
            for key in sorted(VLAN_REQUIRED - set(vlan)):
                err(f"{where}: missing '{key}'")

            # ID
            vid = vlan.get("id")
            if not isinstance(vid, int) or isinstance(vid, bool) or not 2 <= vid <= 4094:
                err(f"{where}: id must be a whole number from 2 to 4094")
            elif vid in RESERVED_VLANS:
                err(f"{where}: VLAN {vid} is reserved, pick another ID")
            elif vid in ids_here:
                err(f"{where}: VLAN ID {vid} is already used by '{ids_here[vid]}' at this site")
            else:
                ids_here[vid] = vlan.get("name", "?")

            # Name
            name = vlan.get("name")
            if not isinstance(name, str) or not NAME_RE.match(name) or len(name) > 32:
                err(f"{where}: name must be lowercase letters, digits and dashes, max 32 chars")
            elif code and not name.startswith(f"{code}-"):
                err(f"{where}: name must start with the site code '{code}-'")
            elif name in vlan_names:
                err(f"{where}: VLAN name '{name}' is also used in {vlan_names[name]}")
            else:
                vlan_names[name] = path

            desc = vlan.get("description", "")
            if not isinstance(desc, str) or len(desc) > 64:
                err(f"{where}: description must be text of at most 64 characters")
            else:
                _check_safe(err, where, "description", desc)

            # Subnet
            net = None
            try:
                net = ipaddress.ip_network(str(vlan.get("subnet")), strict=True)
                if net.version != 4 or not 16 <= net.prefixlen <= 30:
                    err(f"{where}: subnet must be IPv4 with a prefix from /16 to /30")
                    net = None
            except ValueError:
                err(f"{where}: subnet '{vlan.get('subnet')}' is not a valid network "
                    "(host bits must be zero, e.g. 10.10.20.0/24)")
            if net is not None:
                for other, other_where in subnets:
                    if net.overlaps(other):
                        err(f"{where}: subnet {net} overlaps {other} ({other_where})")
                subnets.append((net, where))

            # Devices
            dev_list = vlan.get("devices")
            if not isinstance(dev_list, list) or not dev_list:
                err(f"{where}: 'devices' must be a non-empty list")
                dev_list = []
            if len(set(dev_list)) != len(dev_list):
                err(f"{where}: a device is listed twice in 'devices'")
            for dev_name in dev_list:
                dev = devices.get(dev_name)
                if dev is None:
                    err(f"{where}: device '{dev_name}' is not in data/devices.yml")
                elif dev.get("site") != site_name:
                    err(f"{where}: device '{dev_name}' belongs to site '{dev.get('site')}'")

            # Gateway
            gw = vlan.get("gateway")
            gw_dev = vlan.get("gateway_device")
            gw_ip = None
            if gw is not None:
                try:
                    gw_ip = ipaddress.ip_address(gw)
                except ValueError:
                    err(f"{where}: gateway '{gw}' is not a valid IP address")
                if gw_ip is not None and net is not None:
                    if gw_ip not in net or gw_ip in (net.network_address, net.broadcast_address):
                        err(f"{where}: gateway {gw_ip} must be a usable address inside {net}")
                if gw_ip is not None:
                    if str(gw_ip) in gateways:
                        err(f"{where}: gateway {gw_ip} is also used in {gateways[str(gw_ip)]}")
                    gateways[str(gw_ip)] = where
                if not gw_dev:
                    err(f"{where}: 'gateway' needs a 'gateway_device'")
            if gw_dev:
                if gw is None:
                    err(f"{where}: 'gateway_device' needs a 'gateway'")
                if gw_dev not in dev_list:
                    err(f"{where}: gateway_device '{gw_dev}' must also be listed in 'devices'")
                elif devices.get(gw_dev) and not devices[gw_dev].get("l3"):
                    err(f"{where}: gateway_device '{gw_dev}' is not a layer-3 device (l3: true)")

            # DHCP
            dhcp = vlan.get("dhcp")
            if dhcp is not None:
                if not isinstance(dhcp, dict) or set(dhcp) != {"start", "end"}:
                    err(f"{where}: dhcp needs exactly 'start' and 'end'")
                elif gw_ip is None:
                    err(f"{where}: dhcp needs a gateway")
                elif net is not None:
                    try:
                        start = ipaddress.ip_address(dhcp["start"])
                        end = ipaddress.ip_address(dhcp["end"])
                    except ValueError:
                        err(f"{where}: dhcp start/end must be valid IP addresses")
                    else:
                        hosts_ok = all(
                            a in net and a not in (net.network_address, net.broadcast_address)
                            for a in (start, end)
                        )
                        if not hosts_ok:
                            err(f"{where}: dhcp range must be inside {net}")
                        elif start > end:
                            err(f"{where}: dhcp start {start} is after end {end}")
                        elif start <= gw_ip <= end:
                            err(f"{where}: dhcp range must not include the gateway {gw_ip}")
    return errors


def _check_safe(err, where, label, value):
    if value is None:
        return
    bad = sorted(UNSAFE_CHARS & set(str(value)))
    if bad:
        shown = " ".join(repr(c) for c in bad)
        err(f"{where}: {label} contains characters that are not allowed: {shown}")


def main() -> int:
    try:
        data = load_from_disk()
    except DataError as exc:
        for e in exc.errors:
            print(f"ERROR {e}")
        return 1
    errors = validate(data)
    for e in errors:
        print(f"ERROR {e}")
    vlans = sum(len(s.get("vlans") or []) for s in data["sites"].values() if isinstance(s, dict))
    if errors:
        print(f"\n{len(errors)} error(s) found. Fix them before this change can be deployed.")
        return 1
    print(f"OK: {len(data['devices'])} devices, {len(data['sites'])} sites, {vlans} VLANs. No problems found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
