"""Small client for the MikroTik RouterOS v7 REST API (https://<router>/rest/...).

Enable it on the router with:  /ip service enable www-ssl
Use a dedicated user in a group with only the rights it needs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .http import HttpError, basic_auth, request, tls_context


@dataclass
class RouterOS:
    host: str
    user: str
    password: str
    verify_tls: bool = True
    port: int = 443
    scheme: str = "https"     # "http" only for a lab or a local test server

    @classmethod
    def from_env(cls, host: str | None = None) -> "RouterOS":
        return cls(
            host=host or os.environ["MIKROTIK_HOST"],
            user=os.environ["MIKROTIK_USER"],
            password=os.environ["MIKROTIK_PASSWORD"],
            verify_tls=os.environ.get("MIKROTIK_VERIFY_TLS", "true").lower() != "false",
            port=int(os.environ.get("MIKROTIK_PORT", "443")),
            scheme=os.environ.get("MIKROTIK_SCHEME", "https"),
        )

    # -- raw calls ---------------------------------------------------------
    def _call(self, method: str, path: str, body=None, params=None):
        url = f"{self.scheme}://{self.host}:{self.port}/rest/{path.strip('/')}"
        ctx = tls_context(self.verify_tls) if self.scheme == "https" else None
        return request(method, url, body=body, params=params,
                       headers={"Authorization": basic_auth(self.user, self.password)},
                       context=ctx)

    def get(self, path: str, **params):
        return self._call("GET", path, params=params or None)

    def create(self, path: str, body: dict):
        return self._call("PUT", path, body=body)          # PUT = add a new item

    def update(self, path: str, item_id: str, body: dict):
        return self._call("PATCH", f"{path}/{item_id}", body=body)

    def delete(self, path: str, item_id: str):
        return self._call("DELETE", f"{path}/{item_id}")

    def command(self, path: str, body: dict):
        return self._call("POST", path, body=body)         # POST = run a command

    # -- firewall address lists --------------------------------------------
    def find_address(self, list_name: str, address: str) -> dict | None:
        found = self.get("ip/firewall/address-list", list=list_name, address=address)
        return found[0] if found else None

    def block(self, list_name: str, address: str, timeout: str, comment: str) -> str:
        """Add an IP to an address list (dropped by a firewall rule). Returns 'added' or 'exists'."""
        if self.find_address(list_name, address):
            return "exists"
        self.create("ip/firewall/address-list",
                    {"list": list_name, "address": address, "timeout": timeout, "comment": comment})
        return "added"

    def unblock(self, list_name: str, address: str) -> bool:
        item = self.find_address(list_name, address)
        if not item:
            return False
        self.delete("ip/firewall/address-list", item[".id"])
        return True

    def list_addresses(self, list_name: str) -> list[dict]:
        return self.get("ip/firewall/address-list", list=list_name) or []

    # -- PoE ---------------------------------------------------------------
    def poe_power_cycle(self, interface: str, duration: str = "5s"):
        """Switch PoE off and on again on one port, for a hung camera or access point."""
        return self.command("interface/ethernet/poe/power-cycle",
                            {"numbers": interface, "duration": duration})

    def interface_stats(self, interface: str) -> dict:
        found = self.get("interface", name=interface)
        if not found:
            raise HttpError(404, f"interface {interface} not found", self.host)
        return found[0]
