# 4. Security Onion + CrowdSec: complete monitoring with little setup

Security Onion is one install that gives you Suricata, Zeek, packet capture, Elastic and hunting dashboards. CrowdSec adds community blocklists. The bouncer in this folder pushes CrowdSec's bans to a MikroTik, so the router drops known attackers.

```
WAN ── MikroTik ──port mirror──> Security Onion (Suricata + Zeek + Elastic + hunting)
          ▲
          │ address list "crowdsec-blocked"
          │
 crowdsec_mikrotik_bouncer.py <── CrowdSec LAPI <── your logs (SSH, web server, VPN)
                                         ▲
                                         └── CrowdSec community blocklist (optional)
```

| File | What it does |
| --- | --- |
| `crowdsec_mikrotik_bouncer.py` | Full sync at start, then only the changes every 30 s |
| `mikrotik-setup.rsc` | Drop rule for the list, and the port mirror to Security Onion |
| `netops-crowdsec-bouncer.service` | Runs the bouncer as a service |

## Setup

1. **Security Onion:**
   - Install the ISO on a machine with at least 2 NICs, one for management and one for monitoring (see docs.securityonion.net, "Installation"). Choose "Standalone" for a lab.
   - On the MikroTik, mirror the WAN port to the monitor NIC (`mikrotik-setup.rsc`).
2. **CrowdSec:**
   - Install it on the Linux server whose logs you want watched, for example the VPN or web server, or on the Security Onion box itself: `curl -s https://install.crowdsec.net | sh`, then `apt install crowdsec`.
   - Add the bouncer with `cscli bouncers add mikrotik-bouncer` and put the key in `CROWDSEC_BOUNCER_KEY`.
3. **Bouncer:**
   - Fill in `/etc/netops/env` from `../env.example`.
   - Test it with `NETOPS_DRY_RUN=true python3 crowdsec_mikrotik_bouncer.py --once`.
   - Install the service.
4. **Community blocklist:** add `--include-community` to the service command. Watch your router's memory. On a hEX, keep `--max-entries` around 10000.

Using **pfSense or OPNsense** instead of MikroTik? CrowdSec has an official plugin for both, so you don't need this bouncer.

## Safety built in

- Only entries with a comment starting with `crowdsec` are touched, never your own address-list entries.
- Allowlisted IPs, private ranges and ranges wider than /16 are skipped.
- The list size is capped, and you get a message when it is full.
- Every ban has CrowdSec's own timeout, so it disappears by itself.
