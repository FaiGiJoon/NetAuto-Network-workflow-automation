# Workflows

Six automation setups around the same idea: **detect, decide, act, record**. They share one library (`common/netops/`) with the MikroTik REST client, the safety checks, notifications and tickets.

| # | Folder | Tools | Best for |
| --- | --- | --- | --- |
| 1 | [1-ids-zabbix-autoremediate](1-ids-zabbix-autoremediate/) | Snort/Suricata, Zabbix, MikroTik | Blocking attackers and restarting dead PoE devices automatically |
| 2 | [2-soc-wazuh-thehive](2-soc-wazuh-thehive/) | Suricata, Zeek, Wazuh, TheHive, OPNsense, AbuseIPDB | Learning real security operations |
| 3 | [3-prometheus-grafana](3-prometheus-grafana/) | Prometheus, Grafana, Alertmanager, SNMP, blackbox | Monitoring, dashboards and auto-fixes |
| 4 | [4-security-onion-crowdsec](4-security-onion-crowdsec/) | Security Onion, CrowdSec, MikroTik | A complete security lab with little setup |
| 5 | [5-enterprise-reference](5-enterprise-reference/) | FortiGate, Splunk, PRTG, ServiceNow, ... | Recognising the commercial tools for the same jobs |
| 6 | [6-homelab-uptimekuma-n8n](6-homelab-uptimekuma-n8n/) | Uptime Kuma, ntopng, n8n | Quick, visual home-lab automation |

The main project in the repo root (Git, CI checks, Ansible, Oxidized, LibreNMS, NetBox) covers network **changes**. These workflows cover **running** the network.

## Same safety rules everywhere

- **Dry run first:** with `NETOPS_DRY_RUN=true`, every script only says what it would do.
- **Allowlist:** private ranges and `NETOPS_ALLOWLIST` are never blocked.
- **Rate limits:** a maximum number of blocks per hour and PoE restarts per device per day, then a person takes over.
- **One ticket per problem:** the same key opens at most one ticket per day.
- **Least privilege:** a separate MikroTik user with only REST rights, reachable only from the management network.
- **Secrets** live in `/etc/netops/env` (chmod 600), never in Git. See `env.example`.

## Tests

```bash
python -m unittest discover -s tests     # from the repo root; covers these workflows too
```
