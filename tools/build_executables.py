#!/usr/bin/env python3
"""Build one program per workflow.

  python tools/build_executables.py            single-file executables with PyInstaller
                                               (pip install pyinstaller pyyaml). Builds for the OS
                                               you run it on: run it on Windows to get .exe files.
  python tools/build_executables.py --pyz      single-file .pyz programs (need Python 3.10+, any OS)

Output goes to dist/. GitHub Actions runs this on Windows, Linux and macOS (.github/workflows/build.yml).
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APPS = {
    "netauto": "netauto_cli.py",
    "netops-ids": "netops_ids.py",
    "netops-soc": "netops_soc.py",
    "netops-metrics": "netops_metrics.py",
    "netops-crowdsec": "netops_crowdsec.py",
    "netops-homelab": "netops_homelab.py",
}
NETAUTO_ITEMS = ["data", "scripts", "ansible", "oxidized", "tests/test_pipeline.py", ".gitlab-ci.yml",
                 ".gitignore", "requirements.txt", "requirements-deploy.txt", "README.md"]
IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc")


def platform_tag() -> str:
    system = {"Darwin": "macos"}.get(platform.system(), platform.system().lower())
    machine = {"AMD64": "x86_64", "aarch64": "arm64"}.get(platform.machine(), platform.machine().lower())
    return f"{system}-{machine}"


def stage_resources(dest: Path) -> None:
    """workflows/ and the netauto template, laid out the way _runtime.resource_root() expects."""
    shutil.copytree(ROOT / "workflows", dest / "workflows", ignore=IGNORE, dirs_exist_ok=True)
    for item in NETAUTO_ITEMS:
        src, dst = ROOT / item, dest / "netauto" / item
        if src.is_dir():
            shutil.copytree(src, dst, ignore=IGNORE, dirs_exist_ok=True)
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)


def build_pyinstaller(out: Path, suffix: bool) -> list[Path]:
    try:
        import PyInstaller.__main__ as pyi
    except ImportError:
        sys.exit("PyInstaller is not installed: pip install pyinstaller pyyaml   (or use --pyz)")
    built = []
    with tempfile.TemporaryDirectory() as tmp:
        res = Path(tmp) / "res"
        stage_resources(res)
        for name, script in APPS.items():
            final = f"{name}-{platform_tag()}" if suffix else name
            pyi.run([
                str(ROOT / "apps" / script), "--onefile", "--noconfirm", "--clean",
                "--name", final, "--distpath", str(out),
                "--workpath", str(Path(tmp) / "work"), "--specpath", str(Path(tmp) / "spec"),
                "--paths", str(ROOT / "apps"),
                "--add-data", f"{res / 'workflows'}{os.pathsep}workflows",
                "--add-data", f"{res / 'netauto'}{os.pathsep}netauto",
                "--hidden-import", "yaml",
            ])
            exe = out / (final + (".exe" if platform.system() == "Windows" else ""))
            built.append(exe)
            print(f"built {exe}")
    return built


def build_pyz(out: Path) -> list[Path]:
    import yaml
    built = []
    for name, script in APPS.items():
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp)
            for f in (ROOT / "apps").glob("*.py"):
                shutil.copy2(f, stage / f.name)
            stage_resources(stage)
            shutil.copytree(Path(yaml.__file__).parent, stage / "yaml", ignore=shutil.ignore_patterns(
                "__pycache__", "*.so", "*.pyd"))          # pure-Python PyYAML works everywhere
            module = script.removesuffix(".py")
            (stage / "__main__.py").write_text(f"import sys\nfrom {module} import main\nsys.exit(main())\n")
            target = out / f"{name}.pyz"
            zipapp.create_archive(stage, target, interpreter="/usr/bin/env python3", compressed=True)
            built.append(target)
            print(f"built {target}")
    return built


def smoke_test(files: list[Path]) -> None:
    for f in files:
        cmd = [sys.executable, str(f)] if f.suffix == ".pyz" else [str(f)]
        r = subprocess.run(cmd + ["--version"], capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            sys.exit(f"{f.name} --version failed:\n{r.stdout}\n{r.stderr}")
        print(f"ok  {r.stdout.strip()}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pyz", action="store_true", help="build .pyz programs instead of executables")
    ap.add_argument("--platform-suffix", action="store_true", help="add e.g. -linux-x86_64 to the names")
    ap.add_argument("--out", default=str(ROOT / "dist"))
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    files = build_pyz(out) if args.pyz else build_pyinstaller(out, args.platform_suffix)
    smoke_test(files)
    return 0


if __name__ == "__main__":
    sys.exit(main())
