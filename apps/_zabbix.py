"""Set up the Zabbix side of workflow 1 through the Zabbix API (6.4 / 7.x):
the PoE-restart script, the trigger action, a host group, and the PoE devices
as hosts with the ICMP Ping template and their {$POE_SWITCH}/{$POE_PORT} macros.

Make an API token first: Users > API tokens > Create API token.
"""

from __future__ import annotations

import os

from _runtime import Asker, ok, setup_import_path, step, warn

setup_import_path()

from netops.http import HttpError, request, tls_context  # noqa: E402

SCRIPT_NAME = "netops: PoE restart"
ACTION_NAME = "netops: restart PoE device when unreachable"
GROUP_NAME = "PoE devices"
TRIGGER_TEXT = "Unavailable by ICMP ping"
TEMPLATE = "ICMP Ping"


class ZabbixError(Exception):
    pass


class Zabbix:
    def __init__(self, url: str, token: str, verify: bool = True):
        self.url = url.rstrip("/") + ("" if url.endswith("api_jsonrpc.php") else "/api_jsonrpc.php")
        self.token, self.verify, self._id = token, verify, 0

    def call(self, method: str, params, auth: bool = True):
        self._id += 1
        headers = {"Authorization": f"Bearer {self.token}"} if auth else {}
        ctx = tls_context(self.verify) if self.url.startswith("https") else None
        res = request("POST", self.url, headers=headers, context=ctx,
                      body={"jsonrpc": "2.0", "method": method, "params": params, "id": self._id})
        if isinstance(res, dict) and "error" in res:
            err = res["error"]
            raise ZabbixError(f"{method}: {err.get('message')} {err.get('data', '')}".strip())
        return res["result"]

    # -- idempotent helpers ------------------------------------------------
    def one(self, method: str, **filter_) -> dict | None:
        found = self.call(f"{method}.get", {"output": "extend", "filter": filter_})
        return found[0] if found else None

    def ensure_group(self, name: str) -> str:
        found = self.one("hostgroup", name=name)
        if found:
            return found["groupid"]
        return self.call("hostgroup.create", {"name": name})["groupids"][0]

    def ensure_script(self, command: str) -> tuple[str, str]:
        found = self.one("script", name=SCRIPT_NAME)
        body = {"name": SCRIPT_NAME, "type": 0, "scope": 1, "execute_on": 1, "command": command,
                "description": "Power-cycles the PoE port in {$POE_SWITCH}/{$POE_PORT}. Installed by netops-ids."}
        if found:
            self.call("script.update", {"scriptid": found["scriptid"], **{k: v for k, v in body.items() if k != "name"}})
            return found["scriptid"], "updated"
        return self.call("script.create", body)["scriptids"][0], "created"

    def ensure_action(self, scriptid: str, groupid: str) -> str:
        if self.one("action", name=ACTION_NAME):
            return "exists"
        self.call("action.create", {
            "name": ACTION_NAME, "eventsource": 0, "status": 0, "esc_period": "1h",
            "filter": {"evaltype": 1, "conditions": [
                {"conditiontype": 3, "operator": 2, "value": TRIGGER_TEXT},      # trigger/event name contains
                {"conditiontype": 0, "operator": 0, "value": groupid},           # host group = PoE devices
            ]},
            "operations": [{"operationtype": 1, "opcommand": {"scriptid": scriptid},
                            "opcommand_hst": [{"hostid": "0"}]}],               # 0 = the host with the problem
        })
        return "created"

    def ensure_host(self, name: str, ip: str, groupid: str, templateid: str, switch: str, port: str) -> str:
        host = self.one("host", host=name)
        if host is None:
            self.call("host.create", {
                "host": name, "groups": [{"groupid": groupid}], "templates": [{"templateid": templateid}],
                "interfaces": [{"type": 1, "main": 1, "useip": 1, "ip": ip, "dns": "", "port": "10050"}],
                "macros": [{"macro": "{$POE_SWITCH}", "value": switch}, {"macro": "{$POE_PORT}", "value": port}]})
            return "created"
        for macro, value in (("{$POE_SWITCH}", switch), ("{$POE_PORT}", port)):
            existing = self.call("usermacro.get", {"output": "extend", "hostids": host["hostid"],
                                                   "filter": {"macro": macro}})
            if existing:
                self.call("usermacro.update", {"hostmacroid": existing[0]["hostmacroid"], "value": value})
            else:
                self.call("usermacro.create", {"hostid": host["hostid"], "macro": macro, "value": value})
        return "macros updated"


def setup(a: Asker, default_command: str) -> dict:
    step("Zabbix API (make a token: Users > API tokens)")
    url = a.ask("ZABBIX_URL", "Zabbix web address", "http://localhost:8080", required=True)
    token = a.ask("ZABBIX_TOKEN", "Zabbix API token", secret=True, required=True)
    verify = a.current.get("ZABBIX_VERIFY_TLS", "true") != "false"
    z = Zabbix(url, token, verify)
    try:
        version = z.call("apiinfo.version", {}, auth=False)
        ok(f"Zabbix {version} at {z.url}")
        print("   Where does the Zabbix server find netops-ids? In Docker that is the path inside the container.")
        command_path = a.ask("ZABBIX_NETOPS_PATH", "Path to netops-ids for the Zabbix server", default_command)
        command = f"{command_path} poe-restart --device {{HOST.NAME}} --switch {{$POE_SWITCH}} --port {{$POE_PORT}}"
        groupid = z.ensure_group(GROUP_NAME)
        ok(f"host group '{GROUP_NAME}'")
        scriptid, how = z.ensure_script(command)
        ok(f"script '{SCRIPT_NAME}' {how}")
        ok(f"action '{ACTION_NAME}' {z.ensure_action(scriptid, groupid)}")
        template = z.one("template", host=TEMPLATE)
        if not template:
            warn(f"template '{TEMPLATE}' not found: hosts are not added")
            return {"ZABBIX_URL": url, "ZABBIX_TOKEN": token, "ZABBIX_NETOPS_PATH": command_path}
        import json
        for d in json.loads(a.current.get("ZABBIX_POE_DEVICES") or "[]"):        # for --yes / automation
            ok(f"host {d['name']}: {z.ensure_host(d['name'], d['ip'], groupid, template['templateid'], d['switch'], d['port'])}")
        if not a.non_interactive:
            print("   Add your PoE devices (cameras, access points). Empty name = done.")
            while True:
                name = input("   Device name: ").strip()
                if not name:
                    break
                ip = input("   Device IP: ").strip()
                switch = input("   MikroTik switch IP [{}]: ".format(os.environ.get("MIKROTIK_HOST", ""))).strip() \
                    or os.environ.get("MIKROTIK_HOST", "")
                port = input("   PoE port (e.g. ether4): ").strip()
                ok(f"host {name}: {z.ensure_host(name, ip, groupid, template['templateid'], switch, port)}")
        print("   Note: Zabbix 7 runs scripts only with EnableGlobalScripts=1 (Docker: ZBX_ENABLEGLOBALSCRIPTS=1).")
    except (HttpError, OSError) as exc:
        raise SystemExit(f"Zabbix not reachable: {exc}")
    except ZabbixError as exc:
        raise SystemExit(f"Zabbix refused: {exc} (does the token's user have admin rights?)")
    return {"ZABBIX_URL": url, "ZABBIX_TOKEN": token, "ZABBIX_NETOPS_PATH": command_path}
