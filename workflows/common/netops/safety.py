"""Guard rails for automatic actions: never block your own networks, never
repeat an action too often, and a dry-run switch for testing.

Config through environment variables:
  NETOPS_ALLOWLIST   comma-separated IPs/CIDRs that are never blocked
                     (default: all private ranges + loopback)
  NETOPS_DRY_RUN     "true" = log what would happen, change nothing
  NETOPS_STATE_DIR   where rate-limit state is kept (default /var/lib/netops)
"""

from __future__ import annotations

import ipaddress
import json
import os
import time
from pathlib import Path

DEFAULT_ALLOWLIST = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,100.64.0.0/10,169.254.0.0/16"


def dry_run() -> bool:
    return os.environ.get("NETOPS_DRY_RUN", "false").lower() in ("1", "true", "yes")


def allowlist() -> list:
    raw = os.environ.get("NETOPS_ALLOWLIST", DEFAULT_ALLOWLIST)
    return [ipaddress.ip_network(x.strip(), strict=False) for x in raw.split(",") if x.strip()]


def may_block(ip: str) -> tuple[bool, str]:
    """True only for a valid, public, non-allowlisted address."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, f"'{ip}' is not an IP address"
    for net in allowlist():
        if addr.version == net.version and addr in net:
            return False, f"{ip} is on the allowlist ({net})"
    if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return False, f"{ip} is not a normal host address"
    return True, "ok"


class RateLimiter:
    """Allows an action for a key at most `limit` times per `window` seconds.
    State is kept in a JSON file, so it also works across separate script runs."""

    def __init__(self, name: str, limit: int, window: int, state_dir: str | None = None):
        self.limit, self.window = limit, window
        base = Path(state_dir or os.environ.get("NETOPS_STATE_DIR", "/var/lib/netops"))
        base.mkdir(parents=True, exist_ok=True)
        self.path = base / f"{name}.json"

    def _load(self) -> dict:
        try:
            return json.loads(self.path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def allow(self, key: str, now: float | None = None) -> bool:
        now = now or time.time()
        state = self._load()
        recent = [t for t in state.get(key, []) if now - t < self.window]
        if len(recent) >= self.limit:
            state[key] = recent
            self.path.write_text(json.dumps(state))
            return False
        state[key] = recent + [now]
        self.path.write_text(json.dumps(state))
        return True
