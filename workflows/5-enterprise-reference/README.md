# 5. Enterprise tools: what big companies use for the same jobs

The other workflows are open source. Large companies often do the same jobs with commercial products. This page maps them, so you recognise the names and know which job each one does. There is no code here: these products are licensed and configured through their own consoles.

| Job | Open source in this repo | Common commercial equivalents |
| --- | --- | --- |
| Firewall + IPS | MikroTik / OPNsense + Suricata (1, 2, 4) | Fortinet FortiGate, Palo Alto NGFW, Cisco Secure Firewall (FTD) |
| Firewall logs and reports | Wazuh / Security Onion (2, 4) | FortiAnalyzer, Palo Alto Panorama / Strata Logging |
| SIEM | Wazuh, Security Onion (2, 4) | Splunk, Microsoft Sentinel, IBM QRadar |
| SOAR (automatic response) | `custom-netops-soar.py`, Shuffle (2) | Cortex XSOAR, Splunk SOAR, Sentinel playbooks |
| Network monitoring | Zabbix, LibreNMS, Prometheus (1, 3, netauto) | PRTG, SolarWinds NPM, Auvik |
| Internet and WAN path monitoring | blackbox-exporter ping (3) | Cisco ThousandEyes, Kentik |
| Config backup | Oxidized (netauto) | SolarWinds NCM, BackBox, Unimus |
| Source of truth / IPAM | NetBox (netauto) | Infoblox, BlueCat, Nautobot (open source) |
| Change automation | GitLab CI + Ansible (netauto) | Cisco NSO, Itential, Ansible Automation Platform |
| Ticketing | Jira / GitLab issues / TOPdesk (common/ticket.py) | ServiceNow, TOPdesk, Jira Service Management |

## How the same flow looks there

1. **FortiGate IPS** blocks an attack and logs it to **FortiAnalyzer**.
2. **PRTG** sees the WAN is slow, and **ThousandEyes** shows which provider hop causes it.
3. A **ServiceNow** incident is created automatically and routed to the network team, with the PRTG graph attached.
4. A network engineer makes the fix through **Cisco NSO** or **Ansible Automation Platform**, with approval in ServiceNow.

The ideas are the same as in this repo (detect, decide, act, record, roll back), only with licences, support contracts and one vendor console per job.

## Talking about it in an interview

"I have built this with open-source tools: Suricata, Wazuh, Prometheus, Oxidized, NetBox and Ansible. I know these are the same jobs FortiGate, Splunk, PRTG and ServiceNow do in larger environments, and that switching tools is mostly learning a new console, not a new way of thinking."
