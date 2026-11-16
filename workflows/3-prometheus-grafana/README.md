# 3. Metrics stack: Prometheus + Grafana + Alertmanager + auto-fix

Graphs of every port and every ping, alerts when something breaks, and a small service that fixes known problems on its own.

```
SNMP (switches, routers) ─> snmp-exporter ─┐
ping (every device)      ─> blackbox       ─┼─> Prometheus ─rules─> Alertmanager ─webhook─> remediation_receiver.py
                                            └─> Grafana dashboards                        ├─ DeviceDown + PoE port -> power-cycle
                                                                                          ├─ errors / full link    -> read interface, ticket
                                                                                          └─ everything else       -> ticket + message
```

| File | What it does |
| --- | --- |
| `docker-compose.yml` | The whole stack in one command |
| `prometheus/prometheus.yml` | What to poll: SNMP every 30 s, ping every 15 s |
| `prometheus/targets/*.yml` | Your devices. Cameras get `poe_switch` and `poe_port` labels |
| `prometheus/rules/network.yml` | DeviceDown, PacketLoss, InterfaceDown, InterfaceErrors, LinkSaturated |
| `alertmanager/alertmanager.yml` | Groups alerts, and no packet-loss alert when the device is down anyway |
| `remediation_receiver.py` | Decides per alert: fix, ticket, or message |
| `grafana/` | Data source and a "Network overview" dashboard, loaded automatically |

## Setup

1. Put your devices in `prometheus/targets/snmp.yml` and `icmp.yml`.
2. Turn on SNMP on the devices. The exporter uses community `public` (v2c) by default. For anything real, use SNMPv3: generate an `snmp.yml` with the snmp-exporter generator and mount it.
3. Run `cp ../env.example .env` and fill in MikroTik and notifications. Keep `NETOPS_DRY_RUN=true` at first.
4. Run `docker compose up -d` and open Grafana on port 3000. The "Network overview" dashboard is in the Network folder.
5. Test the receiver without Alertmanager:
   ```bash
   curl -X POST localhost:9095/alert -H 'Content-Type: application/json' \
     -d '{"alerts":[{"status":"firing","labels":{"alertname":"DeviceDown","device":"cam-utr-11","poe_switch":"10.255.10.1","poe_port":"ether7"}}]}'
   ```
   (Port 9095 is only exposed inside Docker. Add `ports: ["127.0.0.1:9095:9095"]` to test from the host.)

## Rundeck or Ansible AWX instead?

`remediation_receiver.py` is deliberately small. In a bigger team you point the Alertmanager webhook at **Rundeck** or **AWX** instead, and every fix becomes a job with logs, approvals and access rights. The mapping from alert to action stays the same.
