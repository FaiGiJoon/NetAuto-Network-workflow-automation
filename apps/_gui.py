"""The NetAuto console: a small local web server for the GUI in gui/.

    netauto gui [--repo .] [--port 8765] [--no-browser] [--debug]

It serves gui/ and a JSON API that runs the real tools:

    GET  /api/status, /api/inventory, /api/netinfo, /api/tools, /api/capture/interfaces
    GET  /api/settings, /api/debug, /api/jobs, /api/jobs/<id>?since=N, /api/files/<capture>
    POST /api/validate, /api/plan, /api/settings, /api/wireshark, /api/debug/client
    POST /api/jobs {"kind": ..., "params": {...}}      start a scan, capture, check ...
    POST /api/jobs/<id>/cancel

Job kinds: checkup (the automated network engineer), ping, traceroute, nmap, wifi,
capture, install, diagnostics, tests, git-status, git-fetch, git-pull, github,
zabbix, program (the check/test of each netops program).

    POST /api/fix {"action", "params", "apply"}   preview or apply a check-up fix
    POST /api/devices/accept                      remember the devices of the last check-up

Safety: it only listens on 127.0.0.1, refuses requests whose Host header is not
local (DNS rebinding), and every API call must carry the session token that is
put into the page when it is served, so other web sites cannot call it. Every
value from the browser is validated before it reaches a command line, and no
command goes through a shell.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import sys
import threading
import time
import webbrowser
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import _toolkit as tk
from _jobs import DebugLog, JobManager

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".json": "application/json",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
    ".txt": "text/plain; charset=utf-8",
}
LOCAL_HOSTS = {"127.0.0.1", "localhost", "[::1]"}
SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/~^@{}-]{0,199}$")
CAPTURE_NAME = re.compile(r"^capture-[0-9-]+\.pcapng$")
MAX_BODY = 64 * 1024
TOKEN_META = '<meta name="netauto-token" content="">'
PROGRAMS = {
    "netops-ids": ("netops_ids", ("check",)),
    "netops-soc": ("netops_soc", ("check", "test")),
    "netops-metrics": ("netops_metrics", ("check",)),
    "netops-crowdsec": ("netops_crowdsec", ("check",)),
    "netops-homelab": ("netops_homelab", ("check",)),
}
DEFAULT_PORT = 8765


def _host_is_local(host_header: str | None) -> bool:
    if not host_header:
        return False
    host = host_header.strip().lower()
    if host.startswith("["):
        host = host.split("]")[0] + "]"
    else:
        host = host.rsplit(":", 1)[0]
    return host in LOCAL_HOSTS


def captures_dir() -> Path:
    from _runtime import default_state_dir
    path = default_state_dir() / "captures"
    path.mkdir(parents=True, exist_ok=True)
    return path


class Api:
    """The JSON endpoints, kept apart from HTTP so tests can call them directly."""

    def __init__(self, repo: Path, scripts: Path, version: str, debug: bool = False):
        self.repo = repo
        self.version = version
        self.token = secrets.token_urlsafe(24)
        self.log = DebugLog(echo=debug)
        self.jobs = JobManager(self.log)
        if str(scripts) not in sys.path:
            sys.path.insert(0, str(scripts))
        self._ifaces: list[dict] = []
        self.last_devices: list[dict] = []

    # ---------------------------------------------------------------- read-only
    def status(self) -> dict:
        return {"version": self.version, "repo": str(self.repo), "system": tk.SYSTEM,
                "has_data": (self.repo / "data" / "devices.yml").exists(),
                "has_tests": (self.repo / "tests").is_dir() and not getattr(sys, "frozen", False)}

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

    def tools(self) -> dict:
        found = {name: tk.find_tool(name) for name in ("nmap", "tshark", "wireshark", "git", "ping", "docker", "winget", "brew")}
        found["traceroute"] = tk.traceroute_tool()
        found["wifi"] = tk.wifi_tool()
        from _runtime import _is_admin
        return {"tools": {k: {"found": bool(v), "path": v or "", "hint": tk.hint("nmcli" if k == "wifi" else k)}
                          for k, v in found.items()},
                "admin": _is_admin(), "system": tk.SYSTEM, "mikrotik": bool(os.environ.get("MIKROTIK_HOST")), "nmap_profiles": {k: v["label"] for k, v in tk.NMAP_PROFILES.items()}}

    def interfaces(self) -> dict:
        items, err = tk.capture_interfaces()
        self._ifaces = items
        return {"interfaces": items, "error": err}

    # ---------------------------------------------------------------- jobs
    def start_job(self, kind: str, params: dict) -> dict:
        params = params if isinstance(params, dict) else {}
        jobs = self.jobs
        if kind == "ping":
            target = tk.validate_target(params.get("target"), allow_network=False)
            count = tk.validate_int(params.get("count", 4), 1, 50, "Count")
            cmd = tk.ping_cmd(target, count)
            job = jobs.start_process("ping", f"Ping {target}", cmd, timeout=30 + count * 3,
                                     on_done=lambda j: tk.parse_ping("\n".join(j.lines)),
                                     encoding=tk.console_encoding(cmd[0]), ok_codes=(0, 1))
        elif kind == "traceroute":
            target = tk.validate_target(params.get("target"), allow_network=False)
            hops = tk.validate_int(params.get("max_hops", 20), 1, 40, "Max hops")
            cmd = tk.trace_cmd(target, hops)
            job = jobs.start_process("traceroute", f"Trace route to {target}", cmd, timeout=240,
                                     on_done=lambda j: {"hops": tk.parse_trace("\n".join(j.lines))},
                                     encoding=tk.console_encoding(cmd[0]), ok_codes=(0, 1))
        elif kind == "nmap":
            target = tk.validate_target(params.get("target"))
            profile = params.get("profile", "discover")
            xml_out = captures_dir() / f"nmap-{secrets.token_hex(4)}.xml"
            cmd = tk.nmap_cmd(target, profile, xml_out)

            def nmap_done(j):
                try:
                    return tk.parse_nmap_xml(xml_out) if xml_out.exists() and xml_out.stat().st_size else {"hosts": []}
                finally:
                    xml_out.unlink(missing_ok=True)
            job = jobs.start_process("nmap", f"nmap {tk.NMAP_PROFILES[profile]['label'].lower()}: {target}", cmd,
                                     timeout=1800, on_done=nmap_done)
        elif kind == "wifi":
            cmd = tk.wifi_cmd()

            def wifi_done(j):
                text = "\n".join(j.lines)
                nets = tk.parse_wifi(text)
                current = tk.connected_ssid_windows()
                for n in nets:
                    n["connected"] = n["connected"] or (current is not None and n["ssid"] == current)
                return {"networks": nets, "summary": tk.wifi_summary(nets), "hint": "" if nets else tk.wifi_hint(text)}
            job = jobs.start_process("wifi", "Wi-Fi scan", cmd, timeout=60, on_done=wifi_done,
                                     encoding=tk.console_encoding(cmd[0]))
        elif kind == "capture":
            if jobs.running("capture"):
                raise tk.BadInput("A capture is already running. Stop it first.")
            if not self._ifaces:
                self.interfaces()
            iface = tk.validate_interface(str(params.get("interface", "")), self._ifaces)
            count = tk.validate_int(params.get("count", 200), 1, 10000, "Packets")
            seconds = tk.validate_int(params.get("seconds", 20), 1, 600, "Seconds")
            bpf = tk.validate_bpf(params.get("filter", ""))
            out = captures_dir() / f"capture-{datetime.now():%Y%m%d-%H%M%S}.pcapng"
            cmd = tk.capture_cmd(iface, count, seconds, bpf, out)
            label = next((i["label"] for i in self._ifaces if i["index"] == iface), iface)

            def capture_done(j):
                rows = tk.read_capture(out)
                return {"file": out.name if out.exists() else "", "path": str(out) if out.exists() else "",
                        "rows": rows, "summary": tk.capture_summary(rows)}
            job = jobs.start_process("capture", f"Capture on {label}" + (f" ({bpf})" if bpf else ""), cmd,
                                     timeout=seconds + 30, on_done=capture_done)
        elif kind == "checkup":
            import _engineer
            opts = {k: bool(params.get(k, True)) for k in ("wifi", "devices", "mikrotik")}

            def checkup(j):
                out = _engineer.run_checkup(j, opts, captures_dir())
                self.last_devices = out.get("devices", [])
                return out
            job = jobs.start_function("checkup", "Network check-up", checkup)
        elif kind == "install":
            tool = params.get("tool")
            job = self._install(tool)
        elif kind == "diagnostics":
            import _diag
            job = jobs.start_function("diagnostics", "Diagnostics: test everything", lambda j: _diag.run_all(self.repo, j))
        elif kind == "tests":
            if not self.status()["has_tests"]:
                raise tk.BadInput("The test suite is only available when you run the console from the source repo.")
            job = jobs.start_process("tests", "Test suite (python -m unittest)",
                                     [sys.executable, "-m", "unittest", "discover", "-s", "tests"], timeout=900,
                                     cwd=str(self.repo), on_done=lambda j: _test_summary(j.lines))
        elif kind == "git-status":
            import _diag
            job = jobs.start_function("git-status", "Git status", lambda j: _diag.git_info(self.repo))
        elif kind in ("git-fetch", "git-pull"):
            git = tk.find_tool("git")
            if not git:
                raise tk.BadInput(f"git was not found. {tk.hint('git')}")
            args = ["fetch", "--prune", "origin"] if kind == "git-fetch" else ["pull", "--ff-only"]
            job = jobs.start_process(kind, f"git {' '.join(args)}", [git, *args], timeout=180, cwd=str(self.repo))
        elif kind == "github":
            import _diag
            job = jobs.start_function("github", "GitHub overview", lambda j: _diag.github_overview(self.repo))
        elif kind == "zabbix":
            import _diag
            job = jobs.start_function("zabbix", "Zabbix overview", lambda j: _diag.zabbix_overview())
        elif kind == "program":
            program, action = params.get("program"), params.get("action", "check")
            if program not in PROGRAMS or action not in PROGRAMS[program][1]:
                raise tk.BadInput("Unknown program or action.")
            module_name = PROGRAMS[program][0]

            def run_program(j):
                mod = _program_module(module_name)
                if program == "netops-metrics" and action == "check":
                    mod.load_config()
                    rc = mod.check(None, attempts=1)               # do not wait 30 s per service
                else:
                    rc = mod.main([action])
                return {"returncode": rc or 0}
            job = jobs.start_function("program", f"{program} {action}", run_program, capture_stdout=True)
        else:
            raise tk.BadInput(f"Unknown job '{kind}'.")
        return job.view()

    def _install(self, tool):
        """One-click install where the OS has a package manager we can run without a password."""
        ids = {"nmap": ("Insecure.Nmap", "nmap"), "tshark": ("WiresharkFoundation.Wireshark", "--cask wireshark"),
               "wireshark": ("WiresharkFoundation.Wireshark", "--cask wireshark"), "git": ("Git.Git", "git")}
        if tool not in ids:
            raise tk.BadInput("Unknown tool.")
        if tk.IS_WINDOWS and tk.find_tool("winget"):
            cmd = [tk.find_tool("winget"), "install", "--id", ids[tool][0], "-e", "--accept-package-agreements",
                   "--accept-source-agreements"]
        elif tk.IS_MAC and tk.find_tool("brew"):
            cmd = [tk.find_tool("brew"), "install", *ids[tool][1].split()]
        else:
            raise tk.BadInput(f"Install it from a terminal: {tk.hint(tool)}")
        return self.jobs.start_process("install", f"Install {tool}", cmd, timeout=1800, encoding=tk.console_encoding(cmd[0]))

    # ---------------------------------------------------------------- other actions
    def capture_file(self, name: str) -> Path | None:
        if not CAPTURE_NAME.match(name or ""):
            return None
        path = captures_dir() / name
        return path if path.is_file() else None

    def open_wireshark(self, body: dict) -> dict:
        path = self.capture_file(body.get("file", ""))
        if not path:
            raise tk.BadInput("That capture file does not exist.")
        return {"ok": True, "program": tk.open_in_wireshark(path)}


def _program_module(name: str):
    """Plain imports (not importlib) so PyInstaller bundles every program into the netauto executable."""
    if name == "netops_ids":
        import netops_ids as mod
    elif name == "netops_soc":
        import netops_soc as mod
    elif name == "netops_metrics":
        import netops_metrics as mod
    elif name == "netops_crowdsec":
        import netops_crowdsec as mod
    else:
        import netops_homelab as mod
    return mod


def _test_summary(lines: list[str]) -> dict:
    text = "\n".join(lines[-40:])
    ran = re.search(r"Ran (\d+) tests? in ([\d.]+)s", text)
    failed = re.search(r"FAILED \((.+)\)", text)
    return {"ran": int(ran.group(1)) if ran else 0, "seconds": float(ran.group(2)) if ran else 0,
            "ok": bool(re.search(r"^OK\b", text, re.M)), "failures": failed.group(1) if failed else ""}


def make_handler(api: Api, gui_root: Path):
    gui_root = gui_root.resolve()

    class Handler(BaseHTTPRequestHandler):
        server_version = "netauto-gui"

        def log_message(self, fmt, *args):  # the debug log replaces the access log
            pass

        # -------------------------------------------------------- helpers
        def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status: int, payload) -> None:
            self._status = status
            self._send(status, json.dumps(payload, default=str).encode("utf-8"), "application/json")

        def _guard(self, api_call: bool) -> bool:
            if not _host_is_local(self.headers.get("Host")):
                self._json(HTTPStatus.FORBIDDEN, {"ok": False, "errors": ["only local requests are allowed"]})
                return False
            if api_call and not secrets.compare_digest(self.headers.get("X-NetAuto-Token", ""), api.token):
                self._json(HTTPStatus.FORBIDDEN, {"ok": False, "errors": ["missing or wrong session token: reload the page"]})
                return False
            return True

        def _route(self, method: str) -> None:
            started = time.time()
            self._status = 200
            parts = urlsplit(self.path)
            path, query = parts.path, parse_qs(parts.query)
            is_api = path.startswith("/api/")
            try:
                if not self._guard(is_api):
                    return
                if not is_api:
                    return self._static(path)
                body = {}
                if method == "POST":
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
                self._api(method, path, query, body)
            except tk.BadInput as exc:
                self._json(400, {"ok": False, "errors": [str(exc)]})
            except RuntimeError as exc:
                self._json(429, {"ok": False, "errors": [str(exc)]})
            except Exception as exc:                                       # noqa: BLE001 - report, never die
                api.log.error("server", f"{method} {path} failed: {exc}", exc)
                self._json(500, {"ok": False, "errors": [f"internal error: {exc}. Details are in the debug log."]})
            finally:
                quiet = re.match(r"^/api/(jobs/[0-9a-f]+|debug)$", path) and method == "GET"
                if is_api and not quiet:
                    level = "error" if self._status >= 500 else "warn" if self._status >= 400 else "info"
                    api.log.add(level, "http", f"{method} {path} -> {self._status} ({(time.time() - started) * 1000:.0f} ms)")

        def _static(self, path: str) -> None:
            rel = "index.html" if path in ("", "/") else path.lstrip("/")
            target = (gui_root / rel).resolve()
            if not target.is_relative_to(gui_root) or not target.is_file():
                self._status = 404
                return self._send(404, b"not found", "text/plain; charset=utf-8")
            data = target.read_bytes()
            if target.name == "index.html":
                data = data.replace(TOKEN_META.encode(), f'<meta name="netauto-token" content="{api.token}">'.encode())
            self._send(200, data, CONTENT_TYPES.get(target.suffix, "application/octet-stream"))

        def _api(self, method: str, path: str, query: dict, body: dict) -> None:
            get = method == "GET"
            if get and path == "/api/status":
                return self._json(200, api.status())
            if get and path == "/api/inventory":
                return self._json(200, api.inventory())
            if get and path == "/api/netinfo":
                return self._json(200, tk.network_info())
            if get and path == "/api/tools":
                return self._json(200, api.tools())
            if get and path == "/api/capture/interfaces":
                return self._json(200, api.interfaces())
            if get and path == "/api/settings":
                import _diag
                return self._json(200, _diag.settings_view())
            if get and path == "/api/debug":
                since = int((query.get("since") or ["0"])[0] or 0)
                return self._json(200, {"log": api.log.since(since), "jobs": api.jobs.recent()})
            if get and path == "/api/jobs":
                return self._json(200, {"jobs": api.jobs.recent()})
            m = re.match(r"^/api/jobs/([0-9a-f]{12})$", path)
            if get and m:
                job = api.jobs.get(m.group(1))
                if not job:
                    return self._json(404, {"ok": False, "errors": ["job not found (the console was restarted?)"]})
                since = int((query.get("since") or ["0"])[0] or 0)
                return self._json(200, job.view(since))
            m = re.match(r"^/api/files/([A-Za-z0-9_.-]+)$", path)
            if get and m:
                file = api.capture_file(m.group(1))
                if not file:
                    return self._json(404, {"ok": False, "errors": ["file not found"]})
                return self._send(200, file.read_bytes(), "application/vnd.tcpdump.pcap",
                                  {"Content-Disposition": f'attachment; filename="{file.name}"'})
            if get:
                return self._json(404, {"ok": False, "errors": ["unknown endpoint"]})
            # POST
            if path == "/api/validate":
                return self._json(200, api.validate())
            if path == "/api/plan":
                status, payload = api.plan(body)
                return self._json(status, payload)
            if path == "/api/jobs":
                return self._json(200, api.start_job(str(body.get("kind", "")), body.get("params") or {}))
            m = re.match(r"^/api/jobs/([0-9a-f]{12})/cancel$", path)
            if m:
                return self._json(200, {"ok": api.jobs.cancel(m.group(1))})
            if path == "/api/settings":
                import _diag
                values = body.get("values")
                if not isinstance(values, dict):
                    return self._json(400, {"ok": False, "errors": ["values must be an object"]})
                saved = _diag.save_settings(values)
                api.log.info("settings", f"saved {', '.join(saved['saved']) or 'nothing'}")
                return self._json(200, {"ok": True, **saved})
            if path == "/api/fix":
                import _engineer
                return self._json(200, _engineer.apply_fix(str(body.get("action", "")), body.get("params") or {},
                                                           bool(body.get("apply")), api.log))
            if path == "/api/devices/accept":
                import _engineer
                count = _engineer.save_baseline(api.last_devices)
                api.log.info("devices", f"{len(api.last_devices)} devices accepted, {count} known")
                return self._json(200, {"ok": True, "known": count})
            if path == "/api/wireshark":
                return self._json(200, api.open_wireshark(body))
            if path == "/api/debug/client":
                api.log.add("error", "browser", str(body.get("message", ""))[:500], str(body.get("detail", ""))[:4000])
                return self._json(200, {"ok": True})
            return self._json(404, {"ok": False, "errors": ["unknown endpoint"]})

        def do_HEAD(self):  # noqa: N802
            self._route("GET")

        def do_GET(self):  # noqa: N802
            self._route("GET")

        def do_POST(self):  # noqa: N802
            self._route("POST")

    return Handler


def make_server(repo: Path, gui_root: Path, scripts: Path, version: str, port: int = DEFAULT_PORT,
                debug: bool = False) -> ThreadingHTTPServer:
    api = Api(repo.resolve(), scripts, version, debug)
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(api, gui_root))
    server.daemon_threads = True
    server.api = api
    return server


def serve(repo: Path, gui_root: Path, scripts: Path, version: str, port: int | None = None,
          open_browser: bool = True, debug: bool = False) -> int:
    """Start the console. Without an explicit port it tries 8765 and, if that port
    is taken or blocked (on Windows, Hyper-V/WSL/Docker reserve port ranges and
    binding to them fails with WinError 10013), falls back to any free port."""
    wanted = DEFAULT_PORT if port is None else port
    try:
        server = make_server(repo, gui_root, scripts, version, wanted, debug)
    except OSError as exc:
        if port is not None:
            print(f"Could not listen on 127.0.0.1:{wanted}: {exc}. Try --port 0 for any free port.")
            return 1
        print(f"Port {wanted} is not available ({exc.strerror or exc}); using a free port instead.")
        try:
            server = make_server(repo, gui_root, scripts, version, 0, debug)
        except OSError as exc2:
            print(f"Could not listen on 127.0.0.1: {exc2}")
            return 1
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"NetAuto console running at {url}  (repo: {repo.resolve()})")
    if debug:
        print("Debug mode: every request and job is printed here.")
    print("Press Ctrl+C to stop.")
    server.api.log.info("server", f"started at {url}, repo {repo.resolve()}")
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
    return 0
