"""Diagnostics for the NetAuto console: is every tool installed, can we capture,
does Git reach its remote, does GitHub answer, and does every configured
service (MikroTik, Zabbix, Prometheus, TheHive, ...) answer with our credentials.

Every check returns {group, name, status, detail, fix}. status is one of
ok, warn, fail, skip. Secrets are never put in a result.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import platform
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

import _toolkit as tk

GITHUB_API = "https://api.github.com"


def result(group: str, name: str, status: str, detail: str = "", fix: str = "") -> dict:
    return {"group": group, "name": name, "status": status, "detail": detail, "fix": fix}


def _http_json(url: str, headers: dict | None = None, timeout: int = 8, verify: bool = True, method: str = "GET",
               body: dict | None = None):
    """Small GET/POST helper that returns (status, json-or-text). Raises OSError when unreachable."""
    import ssl
    ctx = None
    if url.startswith("https"):
        ctx = ssl.create_default_context(cafile=os.environ.get("NETOPS_CA_FILE") or None)
        if not verify:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"Accept": "application/json", "User-Agent": "netauto-console", **(headers or {})}
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read().decode(errors="replace")
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw, status = exc.read().decode(errors="replace"), exc.code
    try:
        return status, json.loads(raw) if raw else None
    except json.JSONDecodeError:
        return status, raw


def redact(text: str) -> str:
    """Remove credentials from URLs and anything that looks like a token."""
    text = re.sub(r"(https?://)[^/@\s]+@", r"\1***@", str(text))
    return re.sub(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b", "***", text)


# ------------------------------------------------------------------ system and tools

def system_checks() -> list[dict]:
    out = []
    v = sys.version_info
    out.append(result("System", "Python", "ok" if v >= (3, 10) else "fail", f"{platform.python_version()} ({sys.executable})",
                      "" if v >= (3, 10) else "Install Python 3.10 or newer from python.org"))
    try:
        import yaml
        out.append(result("System", "PyYAML", "ok", yaml.__version__))
    except ImportError:
        out.append(result("System", "PyYAML", "fail", "not installed", "pip install pyyaml"))
    out.append(result("System", "Operating system", "ok", f"{platform.system()} {platform.release()} ({platform.machine()})"))
    from _runtime import _is_admin
    admin = _is_admin()
    out.append(result("System", "Admin rights", "ok" if admin else "warn",
                      "running as administrator/root" if admin else "running as a normal user",
                      "" if admin else ("Packet capture works through Npcap; nmap OS detection needs 'Run as administrator'."
                                        if tk.IS_WINDOWS else "OS detection and some captures need sudo.")))
    info = tk.network_info()
    out.append(result("System", "Network", "ok" if info["local_ip"] else "warn",
                      f"this computer {info['local_ip'] or '?'}, gateway {info['gateway'] or '?'}",
                      "" if info["local_ip"] else "No network connection found."))
    return out


TOOLS = [
    ("git", "Git", ("--version",), "Needed for plans, fetch/pull and the GitHub connection"),
    ("nmap", "nmap", ("--version",), "Device and port scans"),
    ("tshark", "TShark (Wireshark)", ("--version",), "Packet capture"),
    ("wireshark", "Wireshark", None, "Opening captures in the Wireshark window (optional)"),
    ("ping", "ping", None, "Ping"),
    ("traceroute", "traceroute", None, "Trace route"),
    ("wifi", "Wi-Fi scanner", None, "Wi-Fi scan"),
    ("docker", "Docker", ("--version",), "The Prometheus and home-lab stacks (optional)"),
]


def _tool_check(key: str, label: str, version_args, purpose: str) -> dict:
    if key == "traceroute":
        path = tk.traceroute_tool()
    elif key == "wifi":
        path = tk.wifi_tool()
    else:
        path = tk.find_tool(key)
    optional = key in ("wireshark", "docker")
    if not path:
        fix = tk.hint("nmcli" if key == "wifi" else key)
        return result("Tools", label, "warn" if optional else "fail", f"not found. {purpose}.", fix)
    version = tk.tool_version(path, version_args) if version_args else ""
    return result("Tools", label, "ok", f"{version or path}" + (f"  ({path})" if version else ""))


def tool_checks() -> list[dict]:
    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        return list(pool.map(lambda t: _tool_check(*t), TOOLS))


def capture_check() -> dict:
    if not tk.find_tool("tshark"):
        return result("Tools", "Capture permission", "skip", "tshark is not installed", tk.hint("tshark"))
    items, err = tk.capture_interfaces()
    if items:
        return result("Tools", "Capture permission", "ok", f"{len(items)} interfaces: " + ", ".join(i["label"] for i in items[:6]))
    return result("Tools", "Capture permission", "fail", err)


# ------------------------------------------------------------------ repo and git

def git(repo: Path, *args: str, timeout: int = 20) -> subprocess.CompletedProcess:
    gitbin = tk.find_tool("git")
    if not gitbin:
        raise FileNotFoundError("git")
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="never")
    kwargs = {"creationflags": 0x08000000} if tk.IS_WINDOWS else {}
    return subprocess.run([gitbin, *args], cwd=repo, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout, env=env, **kwargs)


def github_slug(url: str) -> str | None:
    m = re.search(r"github\.com[:/]+([^/\s]+)/([^/\s]+?)(?:\.git)?/?$", url or "")
    return f"{m.group(1)}/{m.group(2)}" if m else None


def git_info(repo: Path) -> dict:
    info = {"is_repo": False}
    if not tk.find_tool("git"):
        return {**info, "error": "git is not installed"}
    r = git(repo, "rev-parse", "--show-toplevel")
    if r.returncode != 0:
        return {**info, "error": "this folder is not a Git repository"}
    info["is_repo"] = True
    info["root"] = r.stdout.strip()
    info["branch"] = git(repo, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    remote = git(repo, "remote", "get-url", "origin")
    info["remote"] = redact(remote.stdout.strip()) if remote.returncode == 0 else ""
    info["github"] = github_slug(remote.stdout.strip()) if remote.returncode == 0 else None
    up = git(repo, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
    info["upstream"] = up.stdout.strip() if up.returncode == 0 else ""
    if info["upstream"]:
        counts = git(repo, "rev-list", "--left-right", "--count", "@{u}...HEAD").stdout.split()
        if len(counts) == 2:
            info["behind"], info["ahead"] = int(counts[0]), int(counts[1])
    status = git(repo, "status", "--porcelain").stdout.splitlines()
    info["changed_files"] = [s[3:] for s in status][:50]
    log = git(repo, "log", "-8", "--pretty=format:%h\t%s\t%an\t%cr").stdout.splitlines()
    info["commits"] = [dict(zip(("hash", "subject", "author", "when"), line.split("\t", 3))) for line in log]
    return info


def repo_checks(repo: Path) -> list[dict]:
    out = []
    data = repo / "data" / "devices.yml"
    out.append(result("Repo", "Network data", "ok" if data.exists() else "warn", str(repo),
                      "" if data.exists() else "Start the console from your netauto repo, or use --repo <folder>"))
    if data.exists():
        try:
            from netlib import DataError, load_from_disk
            from validate import validate
            try:
                d = load_from_disk(repo)
                errors = validate(d)
                out.append(result("Repo", "Data checks (validate)", "ok" if not errors else "fail",
                                  "no problems" if not errors else f"{len(errors)} error(s): {errors[0]}",
                                  "" if not errors else "Open the Change plan page and run the checks"))
            except DataError as exc:
                out.append(result("Repo", "Data checks (validate)", "fail", exc.errors[0]))
        except ImportError as exc:
            out.append(result("Repo", "Data checks (validate)", "fail", f"scripts not found: {exc}"))
    try:
        info = git_info(repo)
    except (OSError, subprocess.SubprocessError) as exc:
        return out + [result("Git", "Repository", "fail", str(exc), tk.hint("git"))]
    if not info.get("is_repo"):
        return out + [result("Git", "Repository", "fail" if "not installed" in info.get("error", "") else "warn",
                             info.get("error", ""), tk.hint("git") if "not installed" in info.get("error", "") else "git init")]
    out.append(result("Git", "Repository", "ok", f"branch {info['branch']} in {info['root']}"))
    if info["changed_files"]:
        out.append(result("Git", "Working tree", "warn", f"{len(info['changed_files'])} changed file(s) not committed",
                          "Commit or stash them before you pull"))
    else:
        out.append(result("Git", "Working tree", "ok", "clean"))
    if not info["remote"]:
        out.append(result("Git", "Remote 'origin'", "warn", "no remote set", "git remote add origin <url>"))
        return out
    out.append(result("Git", "Remote 'origin'", "ok", info["remote"]))
    try:
        r = git(repo, "ls-remote", "--heads", "origin", timeout=25)
        if r.returncode == 0:
            heads = len(r.stdout.splitlines())
            out.append(result("Git", "Connection to origin", "ok", f"reached, {heads} branches"))
        else:
            err = redact(r.stderr.strip().splitlines()[-1] if r.stderr.strip() else f"exit code {r.returncode}")
            fix = ("Sign in once: run 'git fetch' in a terminal (Git Credential Manager opens a browser), "
                   "or use a personal access token") if re.search(r"auth|denied|403|401|credential|terminal prompts", err, re.I) \
                else "Check your internet connection, VPN or proxy"
            out.append(result("Git", "Connection to origin", "fail", err, fix))
    except subprocess.TimeoutExpired:
        out.append(result("Git", "Connection to origin", "fail", "no answer within 25 s", "Check internet, VPN or proxy"))
    if info.get("upstream"):
        behind, ahead = info.get("behind", 0), info.get("ahead", 0)
        state = "up to date" if not behind and not ahead else f"{behind} behind, {ahead} ahead of {info['upstream']}"
        out.append(result("Git", "Branch sync", "ok" if not behind else "warn", state,
                          "Use 'Fetch' and 'Pull' on the Tools page (Git & GitHub)" if behind else ""))
    return out


def github_token() -> str:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""


def github_get(path: str, timeout: int = 10):
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if github_token():
        headers["Authorization"] = f"Bearer {github_token()}"
    return _http_json(f"{GITHUB_API}{path}", headers, timeout=timeout)


def github_checks(repo: Path) -> list[dict]:
    try:
        info = git_info(repo)
    except (OSError, subprocess.SubprocessError):
        info = {}
    slug = info.get("github")
    if not slug:
        return [result("GitHub", "Repository", "skip", "origin is not a GitHub repository")]
    out = []
    try:
        status, body = github_get(f"/repos/{slug}")
    except OSError as exc:
        return [result("GitHub", "API", "fail", f"api.github.com not reachable: {exc}", "Check internet, VPN or proxy")]
    if status == 200:
        out.append(result("GitHub", "Repository", "ok",
                          f"{body.get('full_name')} ({'private' if body.get('private') else 'public'}), default branch {body.get('default_branch')}"))
    elif status == 404:
        out.append(result("GitHub", "Repository", "fail" if not github_token() else "fail",
                          f"{slug} not found or private",
                          "Private repo: set a GitHub token on the Settings page (fine-grained, read access)"))
    else:
        out.append(result("GitHub", "Repository", "fail", f"HTTP {status}: {str(body)[:160]}"))
    if github_token():
        status, body = github_get("/user")
        out.append(result("GitHub", "Token", "ok" if status == 200 else "fail",
                          f"signed in as {body.get('login')}" if status == 200 else f"token refused (HTTP {status})",
                          "" if status == 200 else "Make a new token at github.com/settings/tokens and save it on the Settings page"))
    else:
        out.append(result("GitHub", "Token", "warn", "no token: public data only, 60 API calls an hour",
                          "Optional: add a GitHub token on the Settings page"))
    try:
        status, body = github_get("/rate_limit")
        if status == 200:
            core = body["resources"]["core"]
            out.append(result("GitHub", "API rate limit", "ok" if core["remaining"] > 5 else "warn",
                              f"{core['remaining']} of {core['limit']} calls left this hour"))
    except (OSError, KeyError, TypeError):
        pass
    return out


def github_overview(repo: Path) -> dict:
    info = git_info(repo)
    slug = info.get("github")
    out = {"git": info, "slug": slug, "token": bool(github_token())}
    if not slug:
        return out
    status, body = github_get(f"/repos/{slug}")
    if status == 200:
        out["repo"] = {k: body.get(k) for k in ("full_name", "html_url", "description", "private", "default_branch",
                                                 "open_issues_count", "stargazers_count", "pushed_at")}
    else:
        out["repo_error"] = f"HTTP {status}"
    status, body = github_get(f"/repos/{slug}/pulls?state=open&per_page=10")
    if status == 200:
        out["pulls"] = [{"number": p["number"], "title": p["title"], "user": p["user"]["login"], "url": p["html_url"],
                         "branch": p["head"]["ref"], "draft": p.get("draft", False)} for p in body]
    status, body = github_get(f"/repos/{slug}/actions/runs?per_page=8")
    if status == 200:
        out["runs"] = [{"name": r["name"], "status": r["status"], "conclusion": r.get("conclusion"), "branch": r["head_branch"],
                        "url": r["html_url"], "when": r["created_at"], "event": r["event"]} for r in body.get("workflow_runs", [])]
    return out


# ------------------------------------------------------------------ services

def _env(key: str, default: str = "") -> str:
    return (os.environ.get(key) or default).strip()


def _service(name: str, fn) -> dict:
    try:
        return fn()
    except (OSError, urllib.error.URLError) as exc:
        reason = getattr(exc, "reason", exc)
        return result("Services", name, "fail", f"not reachable: {reason}", "Check the address, the port and the firewall")
    except Exception as exc:                                     # noqa: BLE001 - a broken check must not stop the rest
        return result("Services", name, "fail", f"{type(exc).__name__}: {exc}")


def _http_service(name: str, url: str, headers: dict | None = None, verify: bool = True,
                  ok_text=lambda body: "answers") -> dict:
    status, body = _http_json(url, headers, timeout=6, verify=verify)
    if 200 <= status < 300:
        return result("Services", name, "ok", ok_text(body))
    if status in (401, 403):
        return result("Services", name, "fail", f"refused the credentials (HTTP {status})", "Check the token or password on the Settings page")
    return result("Services", name, "fail", f"HTTP {status}: {str(body)[:140]}")


def _local_optional(name: str, url: str, how: str) -> dict:
    """Stacks that run on this computer by default: not running is not an error."""
    try:
        status, _ = _http_json(url, timeout=3)
        if status < 500:
            return result("Services", name, "ok", f"running at {url.split('/', 3)[2]}")
        return result("Services", name, "warn", f"HTTP {status} at {url}")
    except OSError:
        return result("Services", name, "skip", f"not running on this computer ({how})")


def service_checks() -> list[dict]:
    checks = []
    verify = lambda key: _env(key, "true").lower() != "false"  # noqa: E731

    if _env("MIKROTIK_HOST"):
        def mikrotik():
            from _runtime import setup_import_path
            setup_import_path()
            from netops.http import HttpError
            from netops.mikrotik import RouterOS
            try:
                info = RouterOS.from_env().get("system/resource")
            except HttpError as exc:
                return result("Services", "MikroTik", "fail", f"HTTP {exc.status}: user, password or the rest-api policy",
                              "Check MikroTik user and password on the Settings page")
            except KeyError as exc:
                return result("Services", "MikroTik", "fail", f"setting missing: {exc}", "Fill in MikroTik on the Settings page")
            return result("Services", "MikroTik", "ok", f"{info.get('board-name', '?')}, RouterOS {info.get('version', '?')}, "
                                                        f"uptime {info.get('uptime', '?')}")
        checks.append(("MikroTik", mikrotik))
    else:
        checks.append(("MikroTik", lambda: result("Services", "MikroTik", "skip", "not configured", "Settings: MikroTik")))

    if _env("ZABBIX_URL"):
        def zabbix():
            z = zabbix_client()
            version = z.call("apiinfo.version", {}, auth=False)
            if not _env("ZABBIX_TOKEN"):
                return result("Services", "Zabbix", "warn", f"Zabbix {version}, but no API token", "Settings: Zabbix API token")
            hosts = z.call("host.get", {"countOutput": True})
            return result("Services", "Zabbix", "ok", f"Zabbix {version}, token works, {hosts} hosts")
        checks.append(("Zabbix", zabbix))
    else:
        checks.append(("Zabbix", lambda: result("Services", "Zabbix", "skip", "not configured", "Settings: Zabbix")))

    def add_http(name, key, path, headers_fn=lambda: {}, verify_key=None, ok_text=lambda b: "answers", needs=None):
        base = _env(key)
        if not base or (needs and not _env(needs)):
            checks.append((name, lambda: result("Services", name, "skip", "not configured", f"Settings: {name}")))
            return
        checks.append((name, lambda: _http_service(name, base.rstrip("/") + path, headers_fn(),
                                                   verify(verify_key) if verify_key else True, ok_text)))

    from base64 import b64encode
    basic = lambda u, p: {"Authorization": "Basic " + b64encode(f"{_env(u)}:{_env(p)}".encode()).decode()}  # noqa: E731
    add_http("GitLab", "GITLAB_URL", "/api/v4/version", lambda: {"PRIVATE-TOKEN": _env("GITLAB_TOKEN")},
             ok_text=lambda b: f"GitLab {b.get('version', '?') if isinstance(b, dict) else '?'}")
    add_http("LibreNMS", "LIBRENMS_URL", "/api/v0/system", lambda: {"X-Auth-Token": _env("LIBRENMS_TOKEN")})
    add_http("NetBox", "NETBOX_URL", "/api/status/", lambda: {"Authorization": f"Token {_env('NETBOX_TOKEN')}"},
             ok_text=lambda b: f"NetBox {b.get('netbox-version', '?') if isinstance(b, dict) else '?'}")
    add_http("Oxidized", "OXIDIZED_URL", "/nodes.json", ok_text=lambda b: f"{len(b) if isinstance(b, list) else '?'} nodes")
    add_http("TheHive", "THEHIVE_URL", "/api/v1/user/current", lambda: {"Authorization": f"Bearer {_env('THEHIVE_KEY')}"},
             ok_text=lambda b: f"signed in as {b.get('login', '?') if isinstance(b, dict) else '?'}")
    add_http("OPNsense", "OPNSENSE_URL", "/api/core/firmware/status", lambda: basic("OPNSENSE_KEY", "OPNSENSE_SECRET"),
             verify_key="OPNSENSE_VERIFY_TLS")
    add_http("Jira", "JIRA_URL", "/rest/api/2/myself", lambda: basic("JIRA_USER", "JIRA_TOKEN"),
             ok_text=lambda b: f"signed in as {b.get('displayName', '?') if isinstance(b, dict) else '?'}")
    add_http("CrowdSec", "CROWDSEC_LAPI_URL", "/v1/decisions?ip=127.0.0.1", lambda: {"X-Api-Key": _env("CROWDSEC_BOUNCER_KEY")},
             needs="CROWDSEC_BOUNCER_KEY")
    if _env("ABUSEIPDB_KEY"):
        checks.append(("AbuseIPDB", lambda: _http_service("AbuseIPDB", _env("ABUSEIPDB_URL", "https://api.abuseipdb.com")
                                                           + "/api/v2/check?ipAddress=127.0.0.1", {"Key": _env("ABUSEIPDB_KEY")})))
    else:
        checks.append(("AbuseIPDB", lambda: result("Services", "AbuseIPDB", "skip", "not configured", "Settings: AbuseIPDB")))
    if _env("TELEGRAM_BOT_TOKEN"):
        checks.append(("Telegram", lambda: _http_service("Telegram", f"https://api.telegram.org/bot{_env('TELEGRAM_BOT_TOKEN')}/getMe",
                                                          ok_text=lambda b: f"bot @{(b or {}).get('result', {}).get('username', '?')}")))
    for name, key in (("Teams webhook", "TEAMS_WEBHOOK_URL"), ("Slack webhook", "SLACK_WEBHOOK_URL")):
        if _env(key):
            checks.append((name, lambda name=name: result("Services", name, "ok", "configured (not called: that would post a message)")))

    for name, key, default, how in (
            ("Prometheus", "PROMETHEUS_URL", "http://localhost:9090", "netops-metrics up"),
            ("Alertmanager", "ALERTMANAGER_URL", "http://localhost:9093", "netops-metrics up"),
            ("Grafana", "GRAFANA_URL", "http://localhost:3000", "netops-metrics up"),
            ("Uptime Kuma", "UPTIME_KUMA_URL", "http://localhost:3001", "netops-homelab up"),
            ("n8n", "N8N_URL", "http://localhost:5678", "netops-homelab up")):
        path = {"Prometheus": "/-/ready", "Alertmanager": "/-/ready", "Grafana": "/api/health", "n8n": "/healthz"}.get(name, "/")
        base = _env(key, default).rstrip("/")
        if _env(key):
            checks.append((name, lambda name=name, base=base, path=path: _http_service(name, base + path)))
        else:
            checks.append((name, lambda name=name, base=base, path=path, how=how: _local_optional(name, base + path, how)))

    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        futures = [pool.submit(_service, name, fn) for name, fn in checks]
        return [f.result() for f in futures]


def zabbix_client():
    from _zabbix import Zabbix
    return Zabbix(_env("ZABBIX_URL"), _env("ZABBIX_TOKEN"), _env("ZABBIX_VERIFY_TLS", "true").lower() != "false")


def zabbix_overview() -> dict:
    if not _env("ZABBIX_URL"):
        return {"configured": False}
    z = zabbix_client()
    out = {"configured": True, "url": z.url, "version": z.call("apiinfo.version", {}, auth=False)}
    if not _env("ZABBIX_TOKEN"):
        out["error"] = "No API token: add one on the Settings page."
        return out
    out["hosts"] = int(z.call("host.get", {"countOutput": True}))
    triggers = z.call("trigger.get", {
        "output": ["triggerid", "description", "priority", "lastchange"], "filter": {"value": 1},
        "only_true": True, "monitored": True, "skipDependent": True, "expandDescription": True,
        "selectHosts": ["name"], "sortfield": "priority", "sortorder": "DESC", "limit": 100})
    names = ["Not classified", "Information", "Warning", "Average", "High", "Disaster"]
    out["problems"] = [{"host": ", ".join(h["name"] for h in t.get("hosts", [])), "problem": t["description"],
                        "severity": names[int(t["priority"])] if t["priority"].isdigit() and int(t["priority"]) < 6 else t["priority"],
                        "since": int(t["lastchange"])} for t in triggers]
    return out


# ------------------------------------------------------------------ settings (the shared netops config file)

SETTINGS = [
    ("MikroTik", "MIKROTIK_HOST", "Router address", False, "10.255.10.1"),
    ("MikroTik", "MIKROTIK_USER", "User", False, "netops"),
    ("MikroTik", "MIKROTIK_PASSWORD", "Password", True, ""),
    ("MikroTik", "MIKROTIK_VERIFY_TLS", "Check TLS certificate (true/false)", False, "true"),
    ("Zabbix", "ZABBIX_URL", "Web address", False, "http://zabbix.local:8080"),
    ("Zabbix", "ZABBIX_TOKEN", "API token", True, ""),
    ("Zabbix", "ZABBIX_VERIFY_TLS", "Check TLS certificate (true/false)", False, "true"),
    ("GitHub", "GITHUB_TOKEN", "Personal access token (read access is enough)", True, ""),
    ("GitLab", "GITLAB_URL", "Web address", False, "https://gitlab.com"),
    ("GitLab", "GITLAB_TOKEN", "Access token", True, ""),
    ("GitLab", "GITLAB_PROJECT_ID", "Project ID", False, ""),
    ("Monitoring", "PROMETHEUS_URL", "Prometheus (empty = localhost:9090)", False, ""),
    ("Monitoring", "GRAFANA_URL", "Grafana (empty = localhost:3000)", False, ""),
    ("Monitoring", "LIBRENMS_URL", "LibreNMS address", False, ""),
    ("Monitoring", "LIBRENMS_TOKEN", "LibreNMS API token", True, ""),
    ("Monitoring", "NETBOX_URL", "NetBox address", False, ""),
    ("Monitoring", "NETBOX_TOKEN", "NetBox API token", True, ""),
    ("Monitoring", "OXIDIZED_URL", "Oxidized address", False, ""),
    ("Security", "ABUSEIPDB_KEY", "AbuseIPDB key", True, ""),
    ("Security", "OPNSENSE_URL", "OPNsense address", False, ""),
    ("Security", "OPNSENSE_KEY", "OPNsense API key", True, ""),
    ("Security", "OPNSENSE_SECRET", "OPNsense API secret", True, ""),
    ("Security", "THEHIVE_URL", "TheHive address", False, ""),
    ("Security", "THEHIVE_KEY", "TheHive API key", True, ""),
    ("Security", "CROWDSEC_LAPI_URL", "CrowdSec Local API", False, "http://127.0.0.1:8080"),
    ("Security", "CROWDSEC_BOUNCER_KEY", "CrowdSec bouncer key", True, ""),
    ("Notifications", "TELEGRAM_BOT_TOKEN", "Telegram bot token", True, ""),
    ("Notifications", "TELEGRAM_CHAT_ID", "Telegram chat ID", False, ""),
    ("Notifications", "TEAMS_WEBHOOK_URL", "Teams webhook", True, ""),
    ("Notifications", "SLACK_WEBHOOK_URL", "Slack webhook", True, ""),
    ("Safety", "NETOPS_DRY_RUN", "Dry run: only report, never act (true/false)", False, "true"),
    ("Safety", "NETOPS_ALLOWLIST", "Never block these ranges", False, "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"),
]
SETTING_KEYS = {s[1] for s in SETTINGS}


def settings_view() -> dict:
    from _runtime import config_path, read_config
    stored = read_config()
    fields = []
    for group, key, label, secret, placeholder in SETTINGS:
        value = stored.get(key) or os.environ.get(key, "")
        fields.append({"group": group, "key": key, "label": label, "secret": secret, "placeholder": placeholder,
                       "set": bool(value), "value": "" if secret else value,
                       "from_env": bool(os.environ.get(key)) and not stored.get(key)})
    return {"path": str(config_path()), "fields": fields}


def save_settings(values: dict) -> dict:
    from _runtime import save_config
    updates = {}
    for key, value in values.items():
        if key not in SETTING_KEYS or not isinstance(value, str):
            continue
        value = value.strip()
        if "\n" in value or "\r" in value or len(value) > 2000:
            raise tk.BadInput(f"{key}: one line, at most 2000 characters")
        updates[key] = value
    if updates:
        path = save_config(updates)
        for key, value in updates.items():
            if value:
                os.environ[key] = value
            else:
                os.environ.pop(key, None)
        return {"saved": sorted(updates), "path": str(path)}
    return {"saved": [], "path": ""}


# ------------------------------------------------------------------ all together

def run_all(repo: Path, job) -> dict:
    """The Diagnostics page: runs every group and streams a line per check."""
    groups = [("System", system_checks), ("Tools", lambda: tool_checks() + [capture_check()]),
              ("Repo and Git", lambda: repo_checks(repo)), ("GitHub", lambda: github_checks(repo)),
              ("Services", service_checks)]
    checks: list[dict] = []
    job.result = {"checks": checks}
    icon = {"ok": "OK  ", "warn": "WARN", "fail": "FAIL", "skip": "skip"}
    for label, fn in groups:
        job.log(f"== {label}")
        try:
            items = fn()
        except Exception as exc:                                  # noqa: BLE001
            items = [result(label, "checks", "fail", f"{type(exc).__name__}: {exc}")]
        for item in items:
            checks.append(item)
            job.log(f"{icon[item['status']]}  {item['name']}: {item['detail']}")
    counts = {s: sum(1 for c in checks if c["status"] == s) for s in ("ok", "warn", "fail", "skip")}
    job.log(f"== {counts['ok']} ok, {counts['warn']} warnings, {counts['fail']} failed, {counts['skip']} skipped")
    return {"checks": checks, "counts": counts}
