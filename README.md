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
| `tests/` | 26 tests for the checks and the plan |

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
- Tested here: the checks, the plan and the Oxidized, LibreNMS and NetBox scripts (against a fake server). The Ansible playbooks are written for `community.routeros` and `cisco.ios` but not yet run against real devices. Try them in a lab first (for example GNS3/EVE-NG or a spare MikroTik) with `ansible-playbook deploy.yml --check`.
