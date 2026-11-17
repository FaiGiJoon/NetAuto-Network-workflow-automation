"""netops-homelab: workflow 6. Uptime Kuma + ntopng + n8n, with the PoE-restart
workflow filled in for your devices.

  netops-homelab setup      questions -> writes a ready folder (compose, .env, n8n workflow) and starts it
  netops-homelab up / down  start or stop the stack
  netops-homelab check      are the web interfaces up?
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import _bundle_imports  # noqa: F401  (tells the builder what to include)
from _runtime import VERSION, Asker, _is_admin, fail, load_config, ok, save_config, step, warn, workflow_path

WF = "6-homelab-uptimekuma-n8n"


def default_dir() -> str:
    return "/opt/netops/homelab" if _is_admin() else str(Path.cwd() / "netops-homelab")


def ask_devices(a: Asker) -> dict:
    step("PoE devices that may be restarted (cameras, access points)")
    print("   The name must be the same as the monitor name you give it in Uptime Kuma. Empty name = done.")
    ports = {}
    if a.non_interactive:
        return json.loads(a.current.get("HOMELAB_POE_PORTS") or "{}")
    while True:
        name = input("   Device name: ").strip()
        if not name:
            return ports
        switch = input("   MikroTik switch IP: ").strip()
        port = input("   PoE port (e.g. ether7): ").strip()
        ports[name] = {"switch": switch, "port": port}


def fill_workflow(ports: dict) -> dict:
    wf = json.loads(workflow_path(WF, "n8n-poe-restart-workflow.json").read_text())
    for node in wf["nodes"]:
        if node["type"] == "n8n-nodes-base.code":
            code = node["parameters"]["jsCode"]
            start = code.index("const ports = {")
            end = code.index("};", start) + 2
            node["parameters"]["jsCode"] = code[:start] + "const ports = " + json.dumps(ports, indent=2) + ";" + code[end:]
    return wf


def setup(args) -> int:
    a = Asker(args.yes)
    print("netops-homelab setup. Press Enter to keep the value in [brackets].")
    target = Path(a.ask("HOMELAB_DIR", "Folder for the home-lab stack", default_dir()))
    step("MikroTik (for PoE restarts)")
    user = a.ask("MIKROTIK_USER", "MikroTik user", "netops")
    password = a.ask("MIKROTIK_PASSWORD", "MikroTik password", secret=True)
    step("Telegram (message @BotFather to make a bot, then send it a message and read the chat ID)")
    token = a.ask("TELEGRAM_BOT_TOKEN", "Telegram bot token", secret=True)
    chat = a.ask("TELEGRAM_CHAT_ID", "Telegram chat ID")
    step("ntopng")
    iface = a.ask("NTOPNG_INTERFACE", "Network interface that gets the mirrored traffic", "eth0")
    ports = ask_devices(a)

    save_config({"HOMELAB_DIR": str(target), "MIKROTIK_USER": user, "MIKROTIK_PASSWORD": password,
                 "TELEGRAM_BOT_TOKEN": token, "TELEGRAM_CHAT_ID": chat, "NTOPNG_INTERFACE": iface,
                 "HOMELAB_POE_PORTS": json.dumps(ports, separators=(",", ":"))})
    target.mkdir(parents=True, exist_ok=True)
    shutil.copy2(workflow_path(WF, "docker-compose.yml"), target / "docker-compose.yml")
    basic = base64.b64encode(f"{user}:{password}".encode()).decode() if password else ""
    env = {"MIKROTIK_BASIC_AUTH": basic, "TELEGRAM_BOT_TOKEN": token, "TELEGRAM_CHAT_ID": chat,
           "NTOPNG_INTERFACE": iface}
    (target / ".env").write_text("".join(f"{k}={v}\n" for k, v in env.items()))
    if os.name != "nt":
        os.chmod(target / ".env", 0o600)
    (target / "n8n-poe-restart-workflow.json").write_text(json.dumps(fill_workflow(ports), indent=2))
    ok(f"stack written to {target} ({len(ports)} PoE devices in the n8n workflow)")

    if not args.no_start and a.yes("Start it now with Docker?", True) and compose(target, "up", "-d") == 0:
        if shutil.which("docker"):
            subprocess.run(["docker", "compose", "cp", "n8n-poe-restart-workflow.json", "n8n:/tmp/netops-workflow.json"],
                           cwd=target, capture_output=True)
            imported = subprocess.run(["docker", "compose", "exec", "-T", "n8n", "n8n", "import:workflow",
                                       "--input=/tmp/netops-workflow.json"], cwd=target,
                                      text=True, capture_output=True)
            if imported.returncode == 0:
                ok("n8n workflow imported (activate it in n8n after creating your account)")
            else:
                warn("could not import into n8n automatically yet; import n8n-poe-restart-workflow.json in the n8n web UI")
        print("""
Next, in your browser:
  1. n8n          http://localhost:5678  create the owner account, open the workflow, activate it
  2. Uptime Kuma  http://localhost:3001  add a monitor per device (same names), and a Webhook notification
                  to http://n8n:5678/webhook/uptime-kuma (body: application/json)
  3. ntopng       http://localhost:3002""")
    return 0


def compose(target: Path, *args: str) -> int:
    if not shutil.which("docker"):
        fail("Docker is not installed. Install Docker Engine (docs.docker.com/engine/install) and run again.")
        return 1
    return subprocess.run(["docker", "compose", *args], cwd=target).returncode


def check(_args) -> int:
    from _checks import check_http
    step("Web interfaces")
    results = [check_http("Uptime Kuma", "GET", "http://localhost:3001"),
               check_http("n8n", "GET", "http://localhost:5678/healthz"),
               check_http("ntopng", "GET", "http://localhost:3002")]
    return 0 if all(results) else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="netops-homelab", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"netops-homelab {VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup")
    s.add_argument("--yes", action="store_true")
    s.add_argument("--no-start", action="store_true", help="only write the files")
    for name in ("up", "down", "check"):
        sub.add_parser(name)
    args = ap.parse_args(argv)
    load_config()
    target = Path(os.environ.get("HOMELAB_DIR") or default_dir())
    if args.cmd in ("up", "down"):
        return compose(target, "up", "-d") if args.cmd == "up" else compose(target, "down")
    return {"setup": setup, "check": check}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
