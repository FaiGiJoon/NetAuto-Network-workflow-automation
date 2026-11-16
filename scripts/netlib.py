"""Shared helpers: load the network data (from disk or from any Git commit)
and turn it into the desired state per device."""

from __future__ import annotations

import ipaddress
import subprocess
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = "data"
NULL_SHA = "0" * 40


# ---------------------------------------------------------------- loading

def _parse(text: str, label: str):
    try:
        return yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise DataError([f"{label}: YAML syntax error: {exc}"]) from exc


class DataError(Exception):
    def __init__(self, errors):
        super().__init__("\n".join(errors))
        self.errors = errors


def load_from_disk(root: Path = REPO_ROOT) -> dict:
    data_dir = root / DATA_DIR
    files = {}
    for path in sorted(data_dir.rglob("*.yml")):
        files[str(path.relative_to(root))] = path.read_text(encoding="utf-8")
    return _assemble(files)


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True
    ).stdout


def ref_exists(ref: str | None, root: Path = REPO_ROOT) -> bool:
    if not ref or ref == NULL_SHA:
        return False
    try:
        _git(root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
        return True
    except subprocess.CalledProcessError:
        return False


def load_from_git(ref: str | None, root: Path = REPO_ROOT) -> dict:
    """Load the data as it was at a commit. Unknown ref -> empty network."""
    if not ref_exists(ref, root):
        return {"devices": [], "sites": {}, "_files": {}}
    names = _git(root, "ls-tree", "-r", "--name-only", ref, "--", DATA_DIR).split()
    files = {n: _git(root, "show", f"{ref}:{n}") for n in names if n.endswith(".yml")}
    return _assemble(files)


def _assemble(files: dict[str, str]) -> dict:
    devices, sites = [], {}
    for name, text in files.items():
        parsed = _parse(text, name)
        if name == f"{DATA_DIR}/devices.yml":
            devices = parsed.get("devices") or []
        elif name.startswith(f"{DATA_DIR}/sites/"):
            sites[name] = parsed
    return {"devices": devices, "sites": sites, "_files": files}


# ---------------------------------------------------------- desired state

def desired_state(data: dict) -> dict:
    """{device: {"meta": {...}, "vlans": {vid: {...}}}} — assumes valid data."""
    state = {}
    for dev in data["devices"]:
        state[dev["name"]] = {
            "meta": {
                "platform": dev["platform"],
                "mgmt_ip": dev["mgmt_ip"],
                "bridge": dev.get("bridge"),
                "trunk_ports": list(dev.get("trunk_ports") or []),
            },
            "vlans": {},
        }
    for site in data["sites"].values():
        for vlan in site.get("vlans") or []:
            for dev_name in vlan["devices"]:
                if dev_name not in state:
                    continue
                entry = {
                    "id": vlan["id"],
                    "name": vlan["name"],
                    "description": vlan.get("description", ""),
                    "l3": None,
                    "dhcp": None,
                }
                if vlan.get("gateway_device") == dev_name:
                    net = ipaddress.ip_network(vlan["subnet"])
                    entry["l3"] = {
                        "gateway": vlan["gateway"],
                        "subnet": str(net),
                        "prefixlen": net.prefixlen,
                        "netmask": str(net.netmask),
                    }
                    if vlan.get("dhcp"):
                        entry["dhcp"] = {
                            "start": vlan["dhcp"]["start"],
                            "end": vlan["dhcp"]["end"],
                        }
                state[dev_name]["vlans"][vlan["id"]] = entry
    return state
