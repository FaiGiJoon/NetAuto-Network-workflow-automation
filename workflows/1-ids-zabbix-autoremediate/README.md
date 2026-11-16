# 1. IDS + Zabbix: detect, decide, act, record

Snort or Suricata spots an attacker, the MikroTik blocks it, and a ticket and a message are created automatically. Zabbix spots a dead camera or access point, and the PoE port gets power-cycled.

```
Suricata/Snort ──eve.json──> alert_watcher.py ──> allowlist? rate limit? ──> MikroTik address list (1 day)
                                                                       └──> ticket + Teams/Slack/Telegram
Zabbix trigger "unreachable" ──> zabbix_poe_restart.py ──> PoE power-cycle (max 3x/day) ──> after that: ticket
```

| File | What it does |
| --- | --- |
| `alert_watcher.py` | Follows the alert file. 5 alerts from one IP in 60 s, or one severity-1 alert, means a block |
| `zabbix_poe_restart.py` | Remote command for a Zabbix action |
| `mikrotik-setup.rsc` | Drop rule, limited REST user, HTTPS API, port mirror to the IDS |
| `ids-config/` | Suricata and Snort 3 settings for JSON alerts |
| `netops-alert-watcher.service` | Runs the watcher as a service |

## Setup

1. **MikroTik:** read `mikrotik-setup.rsc` and paste it in, after changing the names and IPs.
2. **IDS:** install Suricata (or Snort 3) on a small Linux box whose NIC gets the mirrored traffic. Turn on JSON alerts with the files in `ids-config/`.
3. **Scripts:** copy the repo to `/opt/netauto`, then `cp workflows/env.example /etc/netops/env`, fill it in, and `chmod 600` it. Create the user and state folder with `useradd -r netops` and `mkdir /var/lib/netops && chown netops /var/lib/netops`.
4. **Test without changing anything:**
   ```bash
   NETOPS_DRY_RUN=true python3 alert_watcher.py --file /var/log/suricata/eve.json --from-start --once
   ```
5. **Run it for real:** set `NETOPS_DRY_RUN=false`, then install the service with `systemctl enable --now netops-alert-watcher`.
6. **Zabbix:**
   - On each camera or access point host, set the macros `{$POE_SWITCH}` (the switch IP) and `{$POE_PORT}` (for example `ether7`).
   - Under Alerts > Scripts, create a script that runs on the Zabbix server:
     `/opt/netauto/workflows/1-ids-zabbix-autoremediate/zabbix_poe_restart.py --device {HOST.NAME} --switch {$POE_SWITCH} --port {$POE_PORT}`
   - Make an action for the "ICMP: Unavailable by ICMP ping" trigger with that script as its operation.

## Safety built in

- Private ranges and anything in `NETOPS_ALLOWLIST` are never blocked.
- At most 20 blocks per hour. Above that, you get a message instead, because it is probably a noisy rule.
- Blocks expire by themselves (default 1 day).
- At most one ticket per IP per day, so an alert storm becomes one ticket.
- PoE restarts are limited to 3 per device per day. After that a person has to look.
