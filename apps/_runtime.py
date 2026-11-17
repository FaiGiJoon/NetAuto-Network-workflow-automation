"""Shared runtime for the netops apps: works the same from source, as a
single-file .pyz, or as a PyInstaller executable.

- finds the bundled files (workflows/, data templates)
- loads and saves the config file (KEY=value lines, chmod 600)
- asks setup questions (with defaults, hidden input for secrets)
- installs a background service (systemd on Linux, a scheduled task on Windows)
"""

from __future__ import annotations

import getpass
import hashlib
import importlib.util
import os
import platform
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

VERSION = "1.0.0"
IS_WINDOWS = platform.system() == "Windows"


# ------------------------------------------------------------ resources

def resource_root() -> Path:
    """Folder that holds the bundled 'workflows' directory."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):        # PyInstaller
        return Path(sys._MEIPASS)
    archive = Path(sys.argv[0]).resolve()
    if archive.is_file() and zipfile.is_zipfile(archive):                 # .pyz
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()[:12]
        target = _cache_dir() / f"bundle-{digest}"
        if not (target / ".complete").exists():
            with zipfile.ZipFile(archive) as z:
                for name in z.namelist():
                    if name.startswith(("workflows/", "netauto/")):
                        z.extract(name, target)
            (target / ".complete").write_text("ok")
        return target
    return Path(__file__).resolve().parent.parent                         # source checkout


def workflow_path(*parts: str) -> Path:
    return resource_root() / "workflows" / Path(*parts)


def setup_import_path() -> None:
    common = str(workflow_path("common"))
    if common not in sys.path:
        sys.path.insert(0, common)


def load_workflow(name: str, relpath: str):
    """Import a workflow script (their folders start with a digit, so no normal import)."""
    setup_import_path()
    spec = importlib.util.spec_from_file_location(name, workflow_path(relpath))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------- config

def _is_admin() -> bool:
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def _cache_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") if IS_WINDOWS else os.environ.get("XDG_CACHE_HOME")
    path = Path(base or Path.home() / ".cache") / "netops"
    path.mkdir(parents=True, exist_ok=True)
    return path


def config_path() -> Path:
    if os.environ.get("NETOPS_CONFIG"):
        return Path(os.environ["NETOPS_CONFIG"])
    if IS_WINDOWS:
        return Path(os.environ.get("APPDATA", Path.home())) / "netops" / "env"
    if _is_admin():
        return Path("/etc/netops/env")
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "netops" / "env"


def default_state_dir() -> Path:
    if IS_WINDOWS:
        return Path(os.environ.get("APPDATA", Path.home())) / "netops" / "state"
    if _is_admin():
        return Path("/var/lib/netops")
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "netops"


def read_config(path: Path | None = None) -> dict:
    path = path or config_path()
    values = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                values[key.strip()] = value.split(" #")[0].strip().strip('"').strip("'")
    return values


def load_config() -> dict:
    """Put the config file into the environment (real environment variables win)."""
    values = read_config()
    for key, value in values.items():
        if value and key not in os.environ:
            os.environ[key] = value
    os.environ.setdefault("NETOPS_STATE_DIR", str(default_state_dir()))
    Path(os.environ["NETOPS_STATE_DIR"]).mkdir(parents=True, exist_ok=True)
    return values


def save_config(updates: dict, path: Path | None = None) -> Path:
    """Merge into the config file, keeping keys other apps wrote."""
    path = path or config_path()
    values = read_config(path)
    values.update({k: v for k, v in updates.items() if v is not None})
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "# netops configuration. Written by the setup wizard; safe to edit.\n"
    text += "".join(f"{k}={v}\n" for k, v in sorted(values.items()))
    path.write_text(text, encoding="utf-8")
    if not IS_WINDOWS:
        os.chmod(path, 0o600)
    for key, value in updates.items():
        if value:
            os.environ[key] = value
    return path


# -------------------------------------------------------------- prompts

class Asker:
    """Asks questions, or with --yes takes the current value without asking."""

    def __init__(self, non_interactive: bool = False):
        self.non_interactive = non_interactive or not sys.stdin.isatty()
        self.current = {**read_config(), **{k: v for k, v in os.environ.items() if k.isupper()}}

    def ask(self, key: str, question: str, default: str = "", secret: bool = False,
            required: bool = False) -> str:
        existing = self.current.get(key) or default
        if self.non_interactive:
            if required and not existing:
                raise SystemExit(f"Missing {key}. Set it in the environment or run setup without --yes.")
            return existing
        shown = ("(saved)" if existing else "") if secret else existing
        while True:
            prompt = f"{question}" + (f" [{shown}]" if shown else "") + ": "
            try:
                answer = getpass.getpass(prompt) if secret else input(prompt)
            except (EOFError, KeyboardInterrupt):
                raise SystemExit("\nSetup stopped. Run setup again to finish; answers so far were not saved.")
            value = answer.strip() or existing
            if value or not required:
                self.current[key] = value
                return value
            print("  This one is needed.")

    def yes(self, question: str, default: bool = True) -> bool:
        if self.non_interactive:
            return default
        try:
            answer = input(f"{question} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            raise SystemExit("\nSetup stopped. Run setup again to finish.")
        return default if not answer else answer in ("y", "yes", "j", "ja")


def step(text: str) -> None:
    print(f"\n== {text}")


def ok(text: str) -> None:
    print(f"   OK   {text}")


def warn(text: str) -> None:
    print(f"   WARN {text}")


def fail(text: str) -> None:
    print(f"   FAIL {text}")


# -------------------------------------------------------------- service

def self_command() -> list[str]:
    """The command that starts this same app again (exe, .pyz or script)."""
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, str(Path(sys.argv[0]).resolve())]


def install_service(name: str, args: list[str], description: str, asker: Asker) -> bool:
    cmd = self_command() + args
    if IS_WINDOWS:
        tr = " ".join(f'"{c}"' if " " in c else c for c in cmd)
        schtasks = ["schtasks", "/Create", "/F", "/TN", name, "/SC", "ONSTART", "/RU", "SYSTEM", "/TR", tr]
        if not _is_admin():
            warn("Run this as administrator to install the background task:")
            print("   " + subprocess.list2cmdline(schtasks))
            return False
        subprocess.run(schtasks, check=True)
        subprocess.run(["schtasks", "/Run", "/TN", name], check=False)
        ok(f"scheduled task '{name}' installed and started")
        return True
    if not shutil.which("systemctl"):
        warn("systemd not found. Start it yourself with: " + " ".join(cmd))
        return False
    unit = f"""[Unit]
Description={description}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=NETOPS_CONFIG={config_path()}
Environment=NETOPS_STATE_DIR={os.environ.get('NETOPS_STATE_DIR', default_state_dir())}
ExecStart={' '.join(cmd)}
Restart=always
RestartSec=10
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
"""
    unit_path = Path(f"/etc/systemd/system/{name}.service")
    if not _is_admin():
        local = Path.cwd() / f"{name}.service"
        local.write_text(unit)
        warn(f"Not root. Wrote {local}. Install it with:")
        print(f"   sudo cp {local} {unit_path} && sudo systemctl daemon-reload && sudo systemctl enable --now {name}")
        return False
    unit_path.write_text(unit)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", name], check=True)
    ok(f"service {name} installed and started (logs: journalctl -u {name} -f)")
    return True
