"""A fake MikroTik RouterOS REST API with insecure settings, for the check-up tests.

    server, state = start_fake_mikrotik()
    os.environ.update(MIKROTIK_HOST="127.0.0.1", MIKROTIK_PORT=str(server.server_address[1]),
                      MIKROTIK_SCHEME="http", MIKROTIK_USER="netops", MIKROTIK_PASSWORD="x")
"""

import copy
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

INSECURE = {
    "system/resource": {"board-name": "hEX S", "version": "7.14.3", "uptime": "3d2h", "cpu-load": "4"},
    "ip/service": [
        {".id": "*0", "name": "telnet", "port": "23", "disabled": "false", "address": ""},
        {".id": "*1", "name": "ftp", "port": "21", "disabled": "false", "address": ""},
        {".id": "*2", "name": "www", "port": "80", "disabled": "false", "address": ""},
        {".id": "*3", "name": "ssh", "port": "22", "disabled": "false", "address": ""},
        {".id": "*4", "name": "api", "port": "8728", "disabled": "false", "address": ""},
        {".id": "*5", "name": "winbox", "port": "8291", "disabled": "false", "address": "10.0.0.0/8"},
        {".id": "*6", "name": "www-ssl", "port": "443", "disabled": "false", "address": ""},
    ],
    "user": [{".id": "*1", "name": "admin", "disabled": "false"}, {".id": "*2", "name": "netops", "disabled": "false"}],
    "ip/upnp": {"enabled": "true"},
    "ip/firewall/filter": [{".id": "*1", "chain": "input", "action": "accept", "disabled": "false"}],
    "ip/dns": {"allow-remote-requests": "true", "servers": "1.1.1.1"},
    "ip/ssh": {"strong-crypto": "false"},
    "interface/list": [{".id": "*1", "name": "LAN"}, {".id": "*2", "name": "WAN"}],
    "ip/neighbor/discovery-settings": {"discover-interface-list": "all"},
    "tool/mac-server": {"allowed-interface-list": "all"},
    "tool/mac-server/mac-winbox": {"allowed-interface-list": "all"},
    "interface": [{".id": "*1", "name": "ether1", "running": "true", "rx-error": "0", "tx-error": "0"},
                  {".id": "*2", "name": "ether3", "running": "true", "rx-error": "5321", "tx-error": "12"}],
    "system/package/update": {"installed-version": "7.14.3", "latest-version": "7.16.1", "channel": "stable"},
}


def start_fake_mikrotik():
    state = copy.deepcopy(INSECURE)
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _reply(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _path(self):
            parts = urlsplit(self.path)
            return parts.path.removeprefix("/rest/").strip("/"), parse_qs(parts.query)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n) or b"{}")

        def do_GET(self):
            path, query = self._path()
            if path not in state:
                return self._reply(404, {"error": 404, "message": "Not Found"})
            data = state[path]
            if isinstance(data, list) and "name" in query:
                data = [d for d in data if d.get("name") == query["name"][0]]
            self._reply(200, data)

        def do_PATCH(self):
            path, _ = self._path()
            base, item = path.rsplit("/", 1)
            body = self._body()
            calls.append(("PATCH", path, body))
            for d in state.get(base, []):
                if d.get(".id") == item:
                    d.update(body)
                    return self._reply(200, d)
            self._reply(404, {"error": 404, "message": "no such item"})

        def do_POST(self):
            path, _ = self._path()
            body = self._body()
            calls.append(("POST", path, body))
            if path.endswith("/set"):
                target = path.removesuffix("/set")
                if isinstance(state.get(target), dict):
                    state[target].update({k: v for k, v in body.items()})
                    return self._reply(200, [])
            if path == "system/package/update/check-for-updates":
                return self._reply(200, [])
            self._reply(400, {"error": 400, "message": "unknown command"})

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, state, calls
