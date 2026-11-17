# 1. IDS + Zabbix: detect, decide, act, record

Suricata (or Snort) spots an attacker, and the MikroTik blocks it with a ticket and a message. Zabbix spots a dead camera or access point, and its PoE port gets power-cycled.

```
Internet ── MikroTik ──(port mirror)──> server: Suricata ──eve.json──> netops-ids ──> address list on the MikroTik (1 day)
               │                                                            └──> ticket + Teams/Slack/Telegram
               └── cameras / APs on PoE  <── power-cycle (max 3x/day) <── Zabbix "Unavailable by ICMP ping"
```

## What you need

- A MikroTik on RouterOS 7. For PoE restarts it must give PoE out, such as a hEX PoE or a PoE switch. The plain hEX only takes PoE in.
- An always-on Linux machine (Ubuntu or Debian) with **two network ports**: one for management, one that receives the mirrored traffic. A USB-to-Ethernet adapter works fine as the second. A home server is ideal. A Raspberry Pi 4 or 5 works for Suricata up to ~300 Mbit/s, but put Zabbix on something stronger.
- One spare device to test blocking with, such as an old phone or a VM.

## Setup, step by step (about 2 hours)

### 1. MikroTik (15 min)
Paste `mikrotik-setup.rsc` into the router's terminal, after changing the IPs and the password. It does five things:
- updates RouterOS
- makes a certificate
- creates a limited `netops` user
- turns on the HTTPS REST API
- mirrors a port to the IDS machine

Check it from your laptop:
```bash
curl -k -u netops:PASSWORD https://<router-ip>/rest/system/resource
```

### 2. Get netops-ids on the server (5 min)
Download `netops-ids-linux-x86_64` from the latest GitHub Actions run (Artifacts) or a Release. Or use `netops-ids.pyz` with Python.
```bash
sudo mkdir -p /opt/netops && sudo mv netops-ids-linux-x86_64 /opt/netops/netops-ids && sudo chmod +x /opt/netops/netops-ids
```

### 3. Run the wizard (30 min, mostly waiting)
```bash
sudo /opt/netops/netops-ids setup
```
- **Dry run:** yes. It only reports what it would block.
- **Router:** its IP, user `netops`. Answer "no" to the TLS check while the certificate is self-signed.
- **Drop rule:** yes. It adds `drop src-address-list=netops-blocked` to the raw table, once.
- **"Install and configure Suricata now?":** yes. This uses the OISF tools:
  - It installs Suricata from the OISF PPA (on Debian, from the normal repository).
  - It lists your network ports and suggests the one without an IP as the mirror port.
  - It sets `HOME_NET` to your own networks and the mirror port in `suricata.yaml` (with a backup).
  - It downloads the rules with **suricata-update**, and offers extra free sources from **suricata-intel-index**: `oisf/trafficid`, abuse.ch SSL and JA3 lists, `tgreen/hunting`.
  - It adds a nightly rule update (`/etc/cron.d/suricata-update`), checks the config with `suricata -T`, and starts Suricata.
- **Service:** yes. netops-ids then runs in the background (`journalctl -u netops-ids -f`).

Run just one part again later with `sudo /opt/netops/netops-ids install-suricata`.

### 4. Check that Suricata sees traffic (5 min)
On a device whose port is mirrored:
```bash
curl http://testmynids.org/uid/index.html
```
On the server:
```bash
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert") | .alert.signature'
```
You should see `GPL ATTACK_RESPONSE id check returned root`. Nothing there? The mirror or the interface is wrong (see Problems).

### 5. Test a real block (15 min)
Your own networks are on the allowlist, so a test from inside never gets blocked. To test anyway:
1. In `/etc/netops/env`, set `NETOPS_ALLOWLIST=127.0.0.0/8,<your-laptop-ip>/32`, then run `sudo systemctl restart netops-ids`.
2. From the test device, run `nmap -sS -T4 <an-ip-on-your-lan>`. The log says `would block <test device>`.
3. Run `sudo /opt/netops/netops-ids setup` again and answer **no** to dry run. Scan again: the test device is now blocked on the MikroTik.
4. Unblock it: `/ip firewall address-list remove [find list=netops-blocked]`. Then put the allowlist back to the default.

### 6. Zabbix with automatic PoE restart (30 min)
1. Start Zabbix with Docker. `zabbix/compose.override.yaml` adds what netops needs: the Ubuntu-based image, scripts switched on, and netops-ids mounted.
   ```bash
   git clone https://github.com/zabbix/zabbix-docker && cd zabbix-docker
   cp /opt/netauto/workflows/1-ids-zabbix-autoremediate/zabbix/compose.override.yaml .
   docker compose -f docker-compose_v3_ubuntu_pgsql_latest.yaml -f compose.override.yaml up -d
   ```
2. Open `http://<server>:8080` and log in with `Admin` / `zabbix`. Change that password straight away. Then go to Users > API tokens and create a token.
3. Run `sudo /opt/netops/netops-ids zabbix-setup`. It does all of this through the Zabbix API:
   - creates the host group "PoE devices"
   - creates the script "netops: PoE restart"
   - creates the action "restart PoE device when unreachable"
   - adds each camera or AP you name, with the ICMP Ping template and its `{$POE_SWITCH}` and `{$POE_PORT}`

   Running it again is safe: it updates instead of duplicating.
4. Test it: unplug a camera's network cable, but not its power. After about 3 minutes Zabbix fires and the port is power-cycled. The fourth time in a day, you get a ticket or message instead.

## Files

| File | What it does |
| --- | --- |
| `alert_watcher.py` | Follows the alert file. 5 alerts from one IP within 60 s, or one severity-1 alert, means a block |
| `zabbix_poe_restart.py` | The PoE restart as a plain script (`netops-ids poe-restart` does the same) |
| `mikrotik-setup.rsc` | Certificate, limited REST user, HTTPS API, port mirror |
| `zabbix/compose.override.yaml` | What Zabbix in Docker needs to run netops-ids |
| `ids-config/` | Suricata and Snort 3 settings for JSON alerts, if you set them up by hand |
| `netops-alert-watcher.service` | systemd unit, if you run the Python script instead of the program |

## Safety built in

- Private ranges and anything in `NETOPS_ALLOWLIST` are never blocked.
- At most 20 blocks per hour. Above that, you get a message instead, because it is probably a noisy rule.
- Blocks expire by themselves (default 1 day). There is at most one ticket per IP per day.
- PoE restarts are limited to 3 per device per day. After that a person has to look.
- The router user can only use the REST API, and only from your LAN.

## Problems

| Problem | Fix |
| --- | --- |
| `check` says the MikroTik is not reachable | Check that www-ssl is on with the certificate, that the `address=` of the user and the service includes the server, and the right IP |
| No alerts in eve.json | Is the mirror going to the right port? Does Suricata listen on that interface (`SURICATA_INTERFACE` in `/etc/netops/env`)? Try mirroring a LAN port instead of WAN |
| `suricata -T` fails after setup | Restore `/etc/suricata/suricata.yaml.netops-backup` and run `install-suricata` again |
| The Zabbix script does nothing | Check `ZBX_ENABLEGLOBALSCRIPTS=1`, whether `/opt/netops/netops-ids` exists inside the container, and run the script by hand from the host menu |
| Too many blocks from one noisy rule | Raise `IDS_THRESHOLD` with `setup`, or disable the rule: add its SID to `/etc/suricata/disable.conf` and run `suricata-update` |
