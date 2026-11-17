# One program per workflow

Every workflow is also a single program. Download it, run `setup`, answer a few questions, and it sets up the rest: it writes the config, tests the connections, adds the firewall rule on the router, and installs the background service.

| Program | Workflow | Most used commands |
| --- | --- | --- |
| `netauto` | VLAN changes through Git (repo root) | `init <folder>`, `validate`, `plan` |
| `netops-ids` | [1. IDS + Zabbix](../workflows/1-ids-zabbix-autoremediate/) | `setup`, `check`, `run`, `install-suricata`, `zabbix-setup`, `poe-restart` |
| `netops-soc` | [2. Wazuh SOC](../workflows/2-soc-wazuh-thehive/) | `setup`, `check`, `test`, `install-wazuh` |
| `netops-metrics` | [3. Prometheus + Grafana](../workflows/3-prometheus-grafana/) | `setup`, `up`, `down`, `check` |
| `netops-crowdsec` | [4. Security Onion + CrowdSec](../workflows/4-security-onion-crowdsec/) | `setup`, `check`, `run`, `sync-once` |
| `netops-homelab` | [6. Uptime Kuma + n8n](../workflows/6-homelab-uptimekuma-n8n/) | `setup`, `up`, `down`, `check` |

Workflow 5 is a reference page only, so it has no program.

## Download

Get the files from the repo's **Releases** page, or from the latest **Actions** run (Artifacts). Each program comes in these versions:

| File | Runs on |
| --- | --- |
| `netops-ids-windows-x86_64.exe` | Windows, nothing else needed |
| `netops-ids-linux-x86_64` | Linux, nothing else needed |
| `netops-ids-macos-arm64` | Mac with Apple silicon, nothing else needed |
| `netops-ids.pyz` | Any system with Python 3.10 or newer: `python3 netops-ids.pyz setup` |

```bash
# Linux
chmod +x netops-ids-linux-x86_64
sudo ./netops-ids-linux-x86_64 setup        # sudo: so it can install the service

# Windows (PowerShell as administrator)
.\netops-ids-windows-x86_64.exe setup

# macOS (the files are not signed, so allow it once)
xattr -d com.apple.quarantine netops-ids-macos-arm64 && chmod +x netops-ids-macos-arm64
./netops-ids-macos-arm64 setup
```

Windows may show a SmartScreen warning because the files are not code-signed. Choose "More info" > "Run anyway".

## What `setup` does for you

| Program | Automatic steps |
| --- | --- |
| `netops-ids` | Tests the MikroTik and adds the raw drop rule once. If Suricata is missing, it installs it from OISF, picks the mirror port, sets HOME_NET, adds the rules (suricata-update) with a nightly update, and starts it. It installs the service, and can create the Zabbix script, action and PoE hosts through the Zabbix API |
| `netops-soc` | Tests AbuseIPDB, OPNsense and TheHive. On the Wazuh manager it also installs the integration, adds it to `ossec.conf` and the rules to `local_rules.xml` (with a backup), and restarts Wazuh |
| `netops-metrics` | Asks for your devices (or imports `data/devices.yml`), writes a complete Docker folder (Prometheus, Alertmanager with a secret token, Grafana, SNMP, remediation service) and starts it |
| `netops-crowdsec` | Registers the bouncer with `cscli` (no copying of keys), tests CrowdSec and the router, adds the drop rule, does a first sync, installs the service |
| `netops-homelab` | Writes the Docker folder, fills the n8n workflow with your devices and PoE ports, starts it and imports the workflow into n8n |
| `netauto` | `init` creates a ready repo: example data, CI pipeline, Ansible, tests and a first Git commit |

Every setup starts in **dry-run mode**: the program only says what it would do. Run `setup` again and answer "n" to dry run once you trust it. Running `setup` again is always safe. Your answers are remembered, and nothing is added twice.

**Without questions** (for scripts or Ansible): put the values in environment variables and run `setup --yes`. Add `--no-service` or `--no-start` to only write the config.

## Where things are kept

| What | Linux (root) | Linux (user) / macOS | Windows |
| --- | --- | --- | --- |
| Config (passwords, chmod 600) | `/etc/netops/env` | `~/.config/netops/env` | `%APPDATA%\netops\env` |
| State (rate limits) | `/var/lib/netops` | `~/.local/state/netops` | `%APPDATA%\netops\state` |
| Service | `systemctl status netops-ids` | (prints the command) | Task Scheduler: `netops-ids` |

All programs share one config file. Set `NETOPS_CONFIG` to use another one.

## Remove

```bash
sudo systemctl disable --now netops-ids && sudo rm /etc/systemd/system/netops-ids.service
sudo rm -r /etc/netops /var/lib/netops      # config and state
```

On Windows, run `schtasks /Delete /TN netops-ids /F` and delete `%APPDATA%\netops`.

## Build them yourself

```bash
pip install pyinstaller pyyaml
python tools/build_executables.py           # executables for the OS you are on, into dist/
python tools/build_executables.py --pyz     # .pyz versions (only needs Python)
```

PyInstaller builds for the system it runs on, so the Windows `.exe` is built on Windows. GitHub Actions does all three automatically (`.github/workflows/build.yml`). Push a tag like `v1.0.0` to get a Release with every file and a `SHA256SUMS.txt`.
