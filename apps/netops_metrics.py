"""netops-metrics: workflow 3. Prometheus + Grafana + Alertmanager + automatic fixes,
generated for your devices and started with Docker.

  netops-metrics setup      questions -> writes a ready-to-run folder and starts it
  netops-metrics up / down  start or stop the stack
  netops-metrics check      is everything running and healthy?
  netops-metrics receiver   run the remediation service without Docker
"""

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

import yaml

import _bundle_imports  # noqa: F401  (tells the builder what to include)
from _runtime import (VERSION, Asker, fail, load_config, load_workflow, ok, read_config, save_config,
                      step, warn, workflow_path, _is_admin)
from _wizard import ask_mikrotik, ask_notifications, ask_safety, ask_tickets

WF = "3-prometheus-grafana"


def default_dir() -> str:
    return "/opt/netops/metrics" if _is_admin() else str(Path.cwd() / "netops-metrics")


def ask_devices(a: Asker) -> list[dict]:
    step("Devices to monitor")
    netauto = a.ask("NETOPS_DEVICES_FILE", "Path to a netauto data/devices.yml to import (Enter to type devices)")
    devices = []
    if netauto and Path(netauto).exists():
        for d in (yaml.safe_load(Path(netauto).read_text()) or {}).get("devices", []):
            devices.append({"name": d["name"], "ip": d["mgmt_ip"], "role": "network", "site": d.get("site", "")})
        ok(f"imported {len(devices)} devices from {netauto}")
    if a.non_interactive:
        return devices
    print("   Add devices one by one. Leave the name empty to stop.")
    print("   Roles: network (switch/router, also polled over SNMP), camera, ap, server, other.")
    while True:
        name = input("   Device name: ").strip()
        if not name:
            break
        ip = input("   IP address: ").strip()
        role = input("   Role [network]: ").strip() or "network"
        dev = {"name": name, "ip": ip, "role": role}
        if role in ("camera", "ap") and a.yes("   Powered by PoE on a MikroTik (so it can be restarted)?", True):
            dev["poe_switch"] = input("   MikroTik switch IP: ").strip()
            dev["poe_port"] = input("   PoE port (e.g. ether7): ").strip()
        devices.append(dev)
    return devices


def write_stack(target: Path, devices: list[dict], cfg: dict, community: str) -> None:
    src = workflow_path(WF)
    target.mkdir(parents=True, exist_ok=True)
    for folder in ("prometheus", "alertmanager", "blackbox", "grafana"):
        shutil.copytree(src / folder, target / folder, dirs_exist_ok=True)

    # Targets from the answers.
    snmp = [{"targets": [d["ip"]], "labels": {"device": d["name"], **({"site": d["site"]} if d.get("site") else {})}}
            for d in devices if d["role"] == "network"]
    icmp = []
    for d in devices:
        labels = {"device": d["name"], "role": d["role"]}
        if d.get("poe_port"):
            labels |= {"poe_switch": d["poe_switch"], "poe_port": d["poe_port"]}
        icmp.append({"targets": [d["ip"]], "labels": labels})
    (target / "prometheus/targets/snmp.yml").write_text(yaml.safe_dump(snmp, sort_keys=False))
    (target / "prometheus/targets/icmp.yml").write_text(yaml.safe_dump(icmp, sort_keys=False))

    # SNMP community in its own auth file, used next to the exporter's built-in modules.
    (target / "snmp-auth.yml").write_text(yaml.safe_dump({"auths": {"netops": {"community": community, "version": 2}}}))
    prom = yaml.safe_load((target / "prometheus/prometheus.yml").read_text())
    for job in prom["scrape_configs"]:
        if job["job_name"] == "snmp":
            job["params"]["auth"] = ["netops"]
    (target / "prometheus/prometheus.yml").write_text(yaml.safe_dump(prom, sort_keys=False))

    # Alertmanager -> receiver with a shared secret.
    am = yaml.safe_load((target / "alertmanager/alertmanager.yml").read_text())
    am["receivers"][0]["webhook_configs"][0]["http_config"] = {
        "authorization": {"type": "Bearer", "credentials": cfg["REMEDIATION_TOKEN"]}}
    (target / "alertmanager/alertmanager.yml").write_text(yaml.safe_dump(am, sort_keys=False))

    # The remediation service: its code goes next to the stack.
    app = target / "remediation/workflows"
    shutil.copytree(workflow_path("common"), app / "common", dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__"))
    (app / WF).mkdir(parents=True, exist_ok=True)
    shutil.copy2(src / "remediation_receiver.py", app / WF / "remediation_receiver.py")

    compose = yaml.safe_load((src / "docker-compose.yml").read_text())
    svc = compose["services"]
    svc["snmp-exporter"]["volumes"] = ["./snmp-auth.yml:/etc/snmp_exporter/auth.yml:ro"]
    svc["snmp-exporter"]["command"] = ["--config.file=/etc/snmp_exporter/snmp.yml",
                                       "--config.file=/etc/snmp_exporter/auth.yml"]
    svc["remediation"]["working_dir"] = f"/app/{WF}"
    svc["remediation"]["volumes"] = ["./remediation/workflows:/app:ro", "remediation-state:/state"]
    (target / "docker-compose.yml").write_text(
        "# Generated by netops-metrics setup. Start: netops-metrics up\n" + yaml.safe_dump(compose, sort_keys=False))

    env = {k: v for k, v in cfg.items() if v}
    env["NETOPS_STATE_DIR"] = "/state"
    (target / ".env").write_text("".join(f"{k}={v}\n" for k, v in sorted(env.items())))
    if os.name != "nt":
        os.chmod(target / ".env", 0o600)


def compose(target: Path, *args: str) -> int:
    if not shutil.which("docker"):
        fail("Docker is not installed. Install Docker Engine (docs.docker.com/engine/install) and run again.")
        return 1
    return subprocess.run(["docker", "compose", *args], cwd=target).returncode


def stack_dir() -> Path:
    return Path(os.environ.get("NETOPS_METRICS_DIR") or default_dir())


def setup(args) -> int:
    a = Asker(args.yes)
    print("netops-metrics setup. Press Enter to keep the value in [brackets].")
    cfg = {"NETOPS_METRICS_DIR": a.ask("NETOPS_METRICS_DIR", "Folder for the monitoring stack", default_dir())}
    cfg |= ask_safety(a)
    devices = ask_devices(a)
    if not devices:
        warn("no devices yet: the stack starts empty. Add them later in prometheus/targets/*.yml")
    step("SNMP")
    community = a.ask("SNMP_COMMUNITY", "SNMP v2c community of your switches/routers", "public", secret=True)
    step("Grafana")
    cfg["GRAFANA_ADMIN_PASSWORD"] = a.ask("GRAFANA_ADMIN_PASSWORD", "Grafana admin password",
                                          secrets.token_urlsafe(12), secret=True)
    if any(d.get("poe_port") for d in devices) or a.yes("Let the remediation service read MikroTik interfaces/PoE?", False):
        cfg |= ask_mikrotik(a)
    cfg |= ask_notifications(a) | ask_tickets(a)
    cfg["REMEDIATION_TOKEN"] = read_config().get("REMEDIATION_TOKEN") or secrets.token_hex(24)
    cfg["SNMP_COMMUNITY"] = community
    save_config(cfg)
    target = Path(cfg["NETOPS_METRICS_DIR"])
    write_stack(target, devices, cfg, community)
    ok(f"stack written to {target}")
    if not args.no_start and a.yes("Start it now with Docker?", True):
        if compose(target, "up", "-d") == 0:
            check(args)
            print(f"\nGrafana: http://localhost:3000  (admin / the password you chose)  Prometheus: http://localhost:9090")
    return 0


def check(_args, attempts: int = 10) -> int:
    step("Stack health")
    good = True
    for label, url in (("Prometheus", "http://localhost:9090/-/ready"), ("Alertmanager", "http://localhost:9093/-/ready"),
                       ("Grafana", "http://localhost:3000/api/health")):
        if _wait(url, attempts):
            ok(f"{label} ready")
        else:
            fail(f"{label} not answering at {url} (docker compose logs in {stack_dir()})")
            good = False
    return 0 if good else 1


def _wait(url: str, attempts: int) -> bool:
    from _runtime import setup_import_path
    setup_import_path()
    from netops.http import request
    for i in range(attempts):
        try:
            request("GET", url, timeout=3)
            return True
        except Exception:
            if i < attempts - 1:
                time.sleep(3)
    return False


def receiver(args) -> int:
    mod = load_workflow("remediation_receiver", f"{WF}/remediation_receiver.py")
    sys.argv = ["remediation_receiver", "--listen", args.listen, "--port", str(args.port)]
    return mod.main()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="netops-metrics", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"netops-metrics {VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup")
    s.add_argument("--yes", action="store_true")
    s.add_argument("--no-start", action="store_true", help="only write the files")
    sub.add_parser("up")
    sub.add_parser("down")
    sub.add_parser("check")
    r = sub.add_parser("receiver")
    r.add_argument("--listen", default="127.0.0.1")
    r.add_argument("--port", type=int, default=9095)
    args = ap.parse_args(argv)
    load_config()
    if args.cmd == "up":
        return compose(stack_dir(), "up", "-d")
    if args.cmd == "down":
        return compose(stack_dir(), "down")
    return {"setup": setup, "check": check, "receiver": receiver}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
