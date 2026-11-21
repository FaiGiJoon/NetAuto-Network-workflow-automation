"""netauto: the Git-based network change pipeline as one program.

  netauto init <folder>          create a new, ready-to-use repo (example data, CI, Ansible, tests)
  netauto validate [--repo .]    run all checks on data/
  netauto plan [--base REF]      show what would change on each device and write build/
  netauto inventory              print the Ansible inventory
  netauto routerdb               print Oxidized's router.db
  netauto gui [--debug]          open the NetAuto console in your browser
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

import _bundle_imports  # noqa: F401  (tells the builder what to include)
from _runtime import VERSION, fail, ok, resource_root, step, warn

TEMPLATE_ITEMS = ["data", "scripts", "ansible", "oxidized", "tests/test_pipeline.py", ".gitlab-ci.yml",
                  ".gitignore", "requirements.txt", "requirements-deploy.txt", "README.md"]


def template_root() -> Path:
    root = resource_root()
    return root / "netauto" if (root / "netauto").exists() else root


def use_scripts() -> None:
    scripts = str(template_root() / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)


def init(args) -> int:
    target = Path(args.folder).resolve()
    if target.exists() and any(target.iterdir()):
        fail(f"{target} is not empty. Pick a new folder.")
        return 1
    src = template_root()
    step(f"Creating a netauto repo in {target}")
    for item in TEMPLATE_ITEMS:
        s, d = src / item, target / item
        if s.is_dir():
            shutil.copytree(s, d, ignore=shutil.ignore_patterns("__pycache__"))
        elif s.exists():
            d.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(s, d)
    ok("files copied: data/, scripts/, ansible/, oxidized/, tests, .gitlab-ci.yml")
    if shutil.which("git"):
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=target, check=False)
        subprocess.run(["git", "add", "-A"], cwd=target, check=False)
        r = subprocess.run(["git", "commit", "-qm", "Start netauto"], cwd=target, capture_output=True)
        ok("git repo created" + ("" if r.returncode == 0 else " (commit it yourself: git user not set)"))
    else:
        warn("git not found: run 'git init' yourself")
    result = validate(argparse.Namespace(repo=str(target)))
    print(f"""
Next:
  1. Put your devices in {target / 'data/devices.yml'} and VLANs in data/sites/
  2. netauto validate --repo {target}
  3. Push it to GitLab and add the CI/CD variables listed at the top of .gitlab-ci.yml""")
    return result


def validate(args) -> int:
    use_scripts()
    from netlib import DataError, load_from_disk
    from validate import validate as run_checks
    repo = Path(args.repo).resolve()
    try:
        data = load_from_disk(repo)
    except DataError as exc:
        for e in exc.errors:
            print(f"ERROR {e}")
        return 1
    errors = run_checks(data)
    for e in errors:
        print(f"ERROR {e}")
    if errors:
        print(f"\n{len(errors)} error(s) found.")
        return 1
    vlans = sum(len(s.get("vlans") or []) for s in data["sites"].values())
    print(f"OK: {len(data['devices'])} devices, {len(data['sites'])} sites, {vlans} VLANs. No problems found.")
    return 0


def plan(args) -> int:
    use_scripts()
    from netlib import DataError
    from plan import build_plan, write_outputs
    repo = Path(args.repo).resolve()
    try:
        result = build_plan(args.base, args.target, repo)
    except DataError as exc:
        for e in exc.errors:
            print(f"ERROR {e}")
        return 1
    out = Path(args.out) if args.out else repo / "build"
    write_outputs(result, out)
    print((out / "plan.md").read_text(encoding="utf-8"))
    return 0


def inventory(args) -> int:
    use_scripts()
    import yaml
    devices = (yaml.safe_load((Path(args.repo) / "data/devices.yml").read_text()) or {}).get("devices", [])
    groups: dict = {"_meta": {"hostvars": {}}}
    for d in devices:
        groups["_meta"]["hostvars"][d["name"]] = {"ansible_host": d["mgmt_ip"]}
        groups.setdefault(d["platform"], {"hosts": []})["hosts"].append(d["name"])
    print(json.dumps(groups, indent=2))
    return 0


def routerdb(args) -> int:
    use_scripts()
    from netlib import load_from_disk
    for d in load_from_disk(Path(args.repo).resolve())["devices"]:
        print(f"{d['name']}:{d['mgmt_ip']}:{d['platform']}:{d['site']}")
    return 0


def gui(args) -> int:
    from _gui import serve
    gui_root = template_root() / "gui"
    if not gui_root.is_dir():
        fail(f"GUI files not found in {gui_root}")
        return 1
    from _runtime import load_config
    load_config()                       # MikroTik, Zabbix, GitHub token ... from the shared netops config
    return serve(Path(args.repo), gui_root, template_root() / "scripts", VERSION,
                 port=args.port, open_browser=not args.no_browser, debug=args.debug)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="netauto", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"netauto {VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init")
    i.add_argument("folder")
    for name in ("validate", "plan", "inventory", "routerdb"):
        p = sub.add_parser(name)
        p.add_argument("--repo", default=".")
        if name == "plan":
            p.add_argument("--base", help="commit on the devices now (default: nothing = add everything)")
            p.add_argument("--target", help="commit to deploy (default: files on disk)")
            p.add_argument("--out")
    g = sub.add_parser("gui", help="open the NetAuto console in your browser")
    g.add_argument("--repo", default=".")
    g.add_argument("--port", type=int, default=None,
                   help="default 8765, or any free port if 8765 is taken; 0 = any free port")
    g.add_argument("--no-browser", action="store_true", help="only print the address")
    g.add_argument("--debug", action="store_true", help="print every request, job and error in this terminal")
    args = ap.parse_args(argv)
    return {"init": init, "validate": validate, "plan": plan, "inventory": inventory, "routerdb": routerdb,
            "gui": gui}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
