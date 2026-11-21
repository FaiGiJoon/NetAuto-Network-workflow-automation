# netauto: network changes through Git

Every VLAN change goes through Git: you describe it in a YAML file, the pipeline checks it, a colleague reviews it, Ansible pushes it, Oxidized backs it up, LibreNMS confirms the network is still up, and a rollback is one button away.

```
 1. Edit data/sites/<site>.yml        (merge request)
        |
 2. validate  ── YAML, naming, VLAN IDs, IP overlaps, gateway/DHCP, unsafe characters
    plan      ── exact commands per device -> build/plan.md (review this!)
        |
    review + merge to main
        |
 3. deploy    ── manual button. Backup first, then push, one device at a time, then verify
        |
 4. verify    ── Oxidized backup + LibreNMS "is everything up?" + NetBox updated
        |
 5. rollback  ── manual button: back to the previous deployed commit
```

## Download the programs

Every workflow is also one ready-to-run program (Windows `.exe`, Linux, macOS, or `.pyz` for any system with Python). Run `setup`, answer a few questions, and it sets up the rest. See [apps/README.md](apps/README.md).

```bash
sudo ./netops-ids-linux-x86_64 setup          # or: netops-ids-windows-x86_64.exe setup
netauto init my-network                       # a new, ready repo for VLAN changes
```

## The NetAuto console (GUI)

A browser console for the whole repo: watch the workflows, and run the real network tools from one place.

```bash
pip install pyyaml
python apps/netauto_cli.py gui            # or: netauto gui
```

It opens `http://127.0.0.1:8765/` (or a free port if 8765 is taken, as on some Windows PCs). Add `--debug` to print every request, job and error in the terminal, `--repo <folder>` for another repo, `--port <n>` for a fixed port.

| Page | What it does |
| --- | --- |
| **Guides** | Explains the six workflows step by step on a network map. Every address and event there is an example, and the page says so: it is not your network |
| **Tools: Network check-up** | Your automated network engineer. Tests gateway and internet (loss, latency), DNS and the DNS servers in use, HTTPS; your Wi-Fi (signal, security, crowded channel and the best channel 1/6/11); every device on your subnet (nmap) for risky open ports (Telnet, FTP, RDP, VNC, plain MikroTik API) and devices that were not there last time; and audits your MikroTik (telnet/ftp/api/www services, UPnP, firewall input drop rule, open DNS resolver, SSH strong-crypto, neighbour discovery and MAC server on the WAN, the default admin user, interface errors, RouterOS updates). Gives a score out of 100 and a fix for every finding. **Fix it** works in three steps for safe router fixes: (1) preview: the RouterOS command and the exact REST call; (2) dry run: reads the current value from your router and changes nothing; (3) apply: only after that dry run, after you tick a confirmation box, and only when `NETOPS_DRY_RUN=false`. Afterwards it reads the value back to prove the change |
| **Tools** | **Wi-Fi scan** (networks, signal, channels, open/WEP warnings), **Network scan** with nmap (devices, open ports, services, OS guess), **Packet capture** with Wireshark's tshark (live table, protocols, top talkers, `.pcapng` download, *Open in Wireshark*), **Ping**, **Trace route**, **Zabbix** (open problems, hosts) and **Git & GitHub** (status, fetch, pull, open PRs, Actions runs) |
| **Inventory** | `data/devices.yml` and the VLANs per site |
| **Change plan** | Runs the checks, and builds the plan against any Git ref |
| **Programs** | Each program with a **Run check** button that tests its config and connections |
| **Diagnostics** | **Run all checks**: Python, every tool, capture rights, the repo data, Git, the connection to GitHub, and every service you set up. Each failure comes with a fix. **Run test suite** runs all unit tests. The **debug log** shows every request, job and error (browser errors too); **Copy debug report** and **Report a bug** (opens a prefilled GitHub issue) |
| **Settings** | MikroTik, Zabbix, GitHub token, GitLab, LibreNMS, NetBox, TheHive, OPNsense, CrowdSec, notifications. Saved in the shared netops config file; secrets are never shown again. **Test connections** checks them right away |

### Look

Omarchy style with Tokyo Night colours: tiled windows with square corners and a lit border on the active tile, a waybar-like top bar with numbered workspaces (keys `1` to `7`) and a clock, JetBrains Mono everywhere (bundled, works offline).

### What to install for the tools

| Tool | Windows | macOS | Linux |
| --- | --- | --- | --- |
| nmap | `winget install Insecure.Nmap`, or the **Install** button on the Tools page | `brew install nmap` | `sudo apt install nmap` |
| Wireshark + tshark | `winget install WiresharkFoundation.Wireshark` (keep TShark and Npcap ticked) | `brew install --cask wireshark` | `sudo apt install tshark` |
| Wi-Fi scan | built in (`netsh`). Windows 11 needs *Settings > Privacy & security > Location* switched on for desktop apps | built in; allow Location for Terminal | `nmcli` (NetworkManager) |
| Git | `winget install Git.Git` | `xcode-select --install` | `sudo apt install git` |

The Diagnostics page tells you which ones are missing. nmap's OS detection needs an administrator or root terminal; captures on Linux need root or the `wireshark` group.

### Safety

Tools never show made-up data. When a tool cannot do its job (program missing, no admin rights, Npcap missing, Location off, nothing captured, nobody answered) the result says so and how to fix it.

The console only listens on `127.0.0.1`, only answers requests for a local host name, and every API call needs a token that is put into the page when it loads, so other web sites cannot use it. Scan targets, capture filters and interfaces are checked before they reach nmap or tshark, and no command goes through a shell. Scans are limited to /20 (4096 addresses). Git can fetch and fast-forward pull, never push. Only scan networks you own or may test.

## More workflows

Besides changes, the repo has six setups for **running** the network. They all follow detect, decide, act, record, and share one safety library. Details are in [workflows/README.md](workflows/README.md).

| # | Setup | What it automates |
| --- | --- | --- |
| 1 | [Snort/Suricata + Zabbix + MikroTik](workflows/1-ids-zabbix-autoremediate/) | Block attackers on the router, power-cycle dead PoE devices |
| 2 | [Suricata + Zeek + Wazuh + TheHive + OPNsense](workflows/2-soc-wazuh-thehive/) | SOC: reputation check, block, case for an analyst |
| 3 | [Prometheus + Grafana + Alertmanager](workflows/3-prometheus-grafana/) | Dashboards, alerts, automatic fixes and diagnostics |
| 4 | [Security Onion + CrowdSec](workflows/4-security-onion-crowdsec/) | Full network security monitoring, community blocklists on the MikroTik |
| 5 | [Enterprise reference](workflows/5-enterprise-reference/) | FortiGate, Splunk, PRTG, ServiceNow: the commercial tools for the same jobs |
| 6 | [Uptime Kuma + ntopng + n8n](workflows/6-homelab-uptimekuma-n8n/) | Home lab: visual automation and Telegram alerts |

## Folder layout

| Path | What it is |
| --- | --- |
| `data/devices.yml` | All managed devices: name, site, platform (`routeros` or `ios`), management IP, trunk ports |
| `data/sites/<site>.yml` | The VLANs per site: ID, name, subnet, gateway, DHCP range |
| `scripts/validate.py` | Step 2: all checks |
| `scripts/plan.py` | Step 2: compares two commits and writes the commands per device |
| `ansible/deploy.yml` | Step 3: pushes the plan (`tasks/routeros.yml`, `tasks/ios.yml`) |
| `scripts/oxidized_backup.py` | Step 4: asks Oxidized for a fresh backup and waits for it |
| `scripts/librenms_check.py` | Step 4: checks in LibreNMS that every changed device is up |
| `scripts/netbox_sync.py` | Step 4: writes VLANs, prefixes and gateways to NetBox (never deletes) |
| `scripts/oxidized_routerdb.py` | Generates Oxidized's `router.db` from `devices.yml` |
| `oxidized/config` | Example Oxidized config (Git output, REST API) |
| `.gitlab-ci.yml` | The pipeline |
| `tests/` | 111 tests (stand-ins such as `tests/fake_mikrotik.py` live only here): the checks, the plan, the workflows, the programs and the console |
| `apps/` | One program per workflow, with a setup wizard |
| `gui/` | The NetAuto console. `netauto gui` serves it: `apps/_gui.py` (server), `_toolkit.py` (nmap, tshark, Wi-Fi, ping), `_jobs.py` (background jobs, debug log), `_diag.py` (diagnostics, Git/GitHub, services, settings), `_engineer.py` (the network check-up and router fixes); `gui/fonts/` JetBrains Mono (OFL) |
| `tools/build_executables.py` | Builds the programs (PyInstaller or .pyz) |
| `workflows/` | Six more automation setups for running the network (see below) |

## Example: add a VLAN for printers in Utrecht

1. Create a branch and add this to `data/sites/utrecht.yml`:

   ```yaml
     - id: 30
       name: utr-printers
       description: Printers
       subnet: 10.10.30.0/24
       gateway: 10.10.30.1
       gateway_device: utr-core-01
       devices: [utr-core-01, utr-sw-01]
       dhcp:
         start: 10.10.30.100
         end: 10.10.30.150
   ```

2. Open a merge request. The pipeline runs `validate` and `plan`. Open the **Network change plan** artifact to see exactly which commands each device will get.
3. A colleague reviews the plan and approves. You merge.
4. On `main`, press **deploy**. Then `verify` runs by itself.

## What the checks catch

- YAML syntax errors and typos in field names (`gatway:` is refused)
- VLAN IDs outside 2-4094, reserved IDs (1, 1002-1005), duplicate IDs at a site
- Names: lowercase, dashes, max 32 characters, must start with the site code (`utr-`)
- Subnets that overlap any other subnet anywhere, or with host bits set (`10.10.30.5/24`)
- Gateway outside the subnet, or equal to the network or broadcast address, or used twice
- Gateway on a switch that cannot route (`l3: false`)
- DHCP range outside the subnet, backwards, or containing the gateway
- Devices that do not exist, or belong to another site
- Characters such as `"` `;` `$` `[` in names and descriptions, so nobody can slip a command into a device

Run them locally before you push:

```bash
pip install -r requirements.txt
python scripts/validate.py
python -m unittest discover -s tests
python scripts/plan.py --base deployed     # what would change compared to the devices
```

## How deploy stays safe

- **Plan first.** The commands in the merge request are exactly the commands that get pushed.
- **Backups first.** RouterOS: a binary backup and an export on the router, plus a copy in the job artifacts. Cisco: the running config is saved to the artifacts before the push.
- **One device at a time.** The first device that fails stops the run.
- **Verify on the device.** After the push, Ansible reads the VLAN table and checks that new VLANs are there and removed ones are gone.
- **Only managed objects.** On RouterOS every object the pipeline creates has the comment `netauto:vlan<id>`, and removals only touch objects with that comment. VLANs you created by hand are left alone.
- **Re-runnable.** Every RouterOS command is "create if missing, otherwise update", so running it twice does no harm.
- **One pipeline at a time.** `resource_group: network` stops two deploys from overlapping.

The pipeline remembers what is on the devices with the Git tag `deployed`, and the commit before that as `previous-deployed`. The plan always compares against `deployed`, so it also sees removals.

## Rollback

**Normal way:** in GitLab, open the merged merge request and press **Revert**. That makes a new merge request that undoes the change. Merge it and press **deploy**. Git and the devices stay in step.

**Fast way, during an outage:** on the latest `main` pipeline, press **rollback**. It plans from `deployed` back to `previous-deployed` and pushes that. To pick another commit, run a pipeline on `main` with the variable `ROLLBACK_TO=<commit sha>`. Afterwards, still revert the merge request, or the next deploy brings the change back.

**Last resort, if a device is unreachable:**
- RouterOS: `/system backup load name=netauto-pre-<pipeline id>` (restores and reboots). Use the console if the network is gone.
- Cisco: take the file from the job artifacts (`build/backups/<device>-pre-<id>.cfg`) or from Oxidized's Git history and restore it with `configure replace`.

## Setting it up

1. **GitLab:** protect `main` and require one approval on merge requests. Add the CI/CD variables listed at the top of `.gitlab-ci.yml`. The runner must be able to reach the devices' management IPs over SSH.
2. **Devices:** create a `netauto` user. RouterOS: SSH on, and bridge VLAN filtering already turned on for the bridge (the pipeline does not turn it on, because that can lock you out). Cisco: SSH on, an enable password, and trunk ports already set to `switchport mode trunk`.
3. **SSH host keys:** collect them with `ssh-keyscan <ip> ...` and store the output in the `SSH_KNOWN_HOSTS` file variable. Host key checking stays on.
4. **Oxidized:** use `oxidized/config`, generate `router.db` with `python scripts/oxidized_routerdb.py`, and expose the REST API to the runner only.
5. **LibreNMS:** add the devices with the same names (or management IPs) and create an API token.
6. **NetBox:** create the sites (slug = site name, e.g. `utrecht`) and an API token.
7. **First run:** there is no `deployed` tag yet, so the plan adds everything. That is safe because the commands only create or update.

## Limits

- Manages VLANs, VLAN interfaces, trunk membership and DHCP. Routing, firewall rules and access ports are left alone. Those are the next things to add.
- On Cisco, the first run assumes the trunk ports already exist. `switchport trunk allowed vlan add` does nothing on a trunk that allows all VLANs.
- RouterOS stores the description only in Git and NetBox (the comment holds the `netauto` tag).
- Tested here: the checks, the plan, the Oxidized, LibreNMS and NetBox scripts, and the workflow scripts (against a fake server). The Ansible playbooks are written for `community.routeros` and `cisco.ios` but not yet run against real devices. Try them in a lab first (for example GNS3/EVE-NG or a spare MikroTik) with `ansible-playbook deploy.yml --check`.
