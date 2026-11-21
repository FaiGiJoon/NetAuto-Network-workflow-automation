"""The NetAuto console: a small local web server for the GUI in gui/.

    netauto gui [--repo .] [--port 8765] [--no-browser]

It serves the static files in gui/ and a few read-only JSON endpoints that run
the same code as the command line:

    GET  /api/status       version and repo folder
    GET  /api/inventory    data/devices.yml and data/sites/*.yml
    POST /api/validate     all checks from scripts/validate.py
    POST /api/plan         {"base": "<ref>"}: what would change on each device

Nothing is written to disk and nothing touches a device. The server only listens
on 127.0.0.1 and refuses requests whose Host header is not local (DNS rebinding).
"""

from __future__ import annotations

import json
import re
import sys
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".json": "application/json",
    ".png": "image/png",
    ".ico": "image/x-icon",
}
LOCAL_HOSTS = {"127.0.0.1", "localhost", "[::1]"}
SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/~^@{}-]{0,199}$")
MAX_BODY = 64 * 1024


def _host_is_local(host_header: str | None) -> bool:
    if not host_header:
        return False
    host = host_header.strip().lower()
    if host.startswith("["):
        host = host.split("]")[0] + "]"
    else:
        host = host.rsplit(":", 1)[0]
    return host in LOCAL_HOSTS


class Api:
    """The JSON endpoints, kept apart from HTTP so tests can call them directly."""

    def __init__(self, repo: Path, scripts: Path, version: str):
        self.repo = repo
        self.version = version
        if str(scripts) not in sys.path:
            sys.path.insert(0, str(scripts))

    def status(self) -> dict:
        return {"version": self.version, "repo": str(self.repo),
                "has_data": (self.repo / "data" / "devices.yml").exists()}

    def inventory(self) -> dict:
        from netlib import DataError, load_from_disk
        try:
            data = load_from_disk(self.repo)
        except DataError as exc:
            return {"ok": False, "errors": exc.errors, "devices": [], "sites": []}
        sites = []
        for path, site in sorted(data["sites"].items()):
            if isinstance(site, dict):
                sites.append({"file": path, "site": site.get("site"), "code": site.get("code"),
                              "vlans": site.get("vlans") or []})
        return {"ok": True, "errors": [], "devices": data["devices"], "sites": sites}

    def validate(self) -> dict:
        from netlib import DataError, load_from_disk
        from validate import validate as run_checks
        try:
            data = load_from_disk(self.repo)
        except DataError as exc:
            return {"ok": False, "errors": exc.errors, "summary": "The data could not be read."}
        errors = run_checks(data)
        vlans = sum(len(s.get("vlans") or []) for s in data["sites"].values() if isinstance(s, dict))
        summary = (f"{len(errors)} error(s) found." if errors else
                   f"{len(data['devices'])} devices, {len(data['sites'])} sites, {vlans} VLANs. No problems found.")
        return {"ok": not errors, "errors": errors, "summary": summary}

    def plan(self, body: dict) -> tuple[int, dict]:
        from netlib import DataError
        from plan import build_plan
        base = (body.get("base") or "").strip() or None
        if base is not None and not SAFE_REF.match(base):
            return 400, {"ok": False, "errors": [f"'{base}' is not a valid Git reference"]}
        try:
            result = build_plan(base, None, self.repo)
        except DataError as exc:
            return 200, {"ok": False, "errors": exc.errors}
        return 200, {"ok": True, "errors": [], **result}


def make_handler(api: Api, gui_root: Path):
    gui_root = gui_root.resolve()

    class Handler(BaseHTTPRequestHandler):
        server_version = "netauto-gui"

        def log_message(self, fmt, *args):  # keep the terminal quiet
            pass

        # -------------------------------------------------------- helpers
        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status: int, payload: dict) -> None:
            self._send(status, json.dumps(payload).encode("utf-8"), "application/json")

        def _guard(self) -> bool:
            if not _host_is_local(self.headers.get("Host")):
                self._json(HTTPStatus.FORBIDDEN, {"ok": False, "errors": ["only local requests are allowed"]})
                return False
            return True

        # --------------------------------------------------------- routes
        def do_HEAD(self):  # noqa: N802
            self.do_GET()

        def do_GET(self):  # noqa: N802
            if not self._guard():
                return
            path = self.path.split("?", 1)[0].split("#", 1)[0]
            if path == "/api/status":
                return self._json(200, api.status())
            if path == "/api/inventory":
                return self._json(200, api.inventory())
            if path.startswith("/api/"):
                return self._json(404, {"ok": False, "errors": ["unknown endpoint"]})
            rel = "index.html" if path in ("", "/") else path.lstrip("/")
            target = (gui_root / rel).resolve()
            if not target.is_relative_to(gui_root) or not target.is_file():
                return self._send(404, b"not found", "text/plain; charset=utf-8")
            ctype = CONTENT_TYPES.get(target.suffix, "application/octet-stream")
            self._send(200, target.read_bytes(), ctype)

        def do_POST(self):  # noqa: N802
            if not self._guard():
                return
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                return self._json(415, {"ok": False, "errors": ["send application/json"]})
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                return self._json(413, {"ok": False, "errors": ["request too large"]})
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return self._json(400, {"ok": False, "errors": ["body must be a JSON object"]})
            path = self.path.split("?", 1)[0]
            if path == "/api/validate":
                return self._json(200, api.validate())
            if path == "/api/plan":
                status, payload = api.plan(body)
                return self._json(status, payload)
            self._json(404, {"ok": False, "errors": ["unknown endpoint"]})

    return Handler


def make_server(repo: Path, gui_root: Path, scripts: Path, version: str, port: int = 8765) -> ThreadingHTTPServer:
    api = Api(repo.resolve(), scripts, version)
    return ThreadingHTTPServer(("127.0.0.1", port), make_handler(api, gui_root))


DEFAULT_PORT = 8765


def serve(repo: Path, gui_root: Path, scripts: Path, version: str, port: int | None = None,
          open_browser: bool = True) -> int:
    """Start the console. Without an explicit port it tries 8765 and, if that port
    is taken or blocked (on Windows, Hyper-V/WSL/Docker reserve port ranges and
    binding to them fails with WinError 10013), falls back to any free port."""
    wanted = DEFAULT_PORT if port is None else port
    try:
        server = make_server(repo, gui_root, scripts, version, wanted)
    except OSError as exc:
        if port is not None:
            print(f"Could not listen on 127.0.0.1:{wanted}: {exc}. Try --port 0 for any free port.")
            return 1
        print(f"Port {wanted} is not available ({exc.strerror or exc}); using a free port instead.")
        try:
            server = make_server(repo, gui_root, scripts, version, 0)
        except OSError as exc2:
            print(f"Could not listen on 127.0.0.1: {exc2}")
            return 1
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"NetAuto console running at {url}  (repo: {repo.resolve()})")
    print("Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
    return 0
