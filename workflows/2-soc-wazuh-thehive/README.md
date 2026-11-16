# 2. SOC stack: Suricata + Zeek + Wazuh + TheHive + OPNsense

Closest to how a real security operations centre works. Sensors see the traffic, Wazuh correlates it with what happens on your servers, and a SOAR step checks the attacker's reputation, blocks it and opens an alert for an analyst.

```
Suricata (IDS)  ─┐
Zeek (behaviour)─┼─> Wazuh manager ──level >= 10──> custom-netops-soar
Wazuh agents   ─┘                                   ├─ AbuseIPDB score >= 75? -> OPNsense alias "netops_blocked"
                                                    ├─ TheHive alert with the IP as observable
                                                    └─ Teams/Slack/Telegram
```

| File | What it does |
| --- | --- |
| `custom-netops-soar.py` | The SOAR logic: lookup, block, TheHive alert, message |
| `custom-netops-soar` | Wrapper that Wazuh calls (loads `/etc/netops/env`) |
| `install.sh` | Copies both into `/var/ossec/integrations/` with the right owner |
| `ossec-integration.xml` | `ossec.conf` blocks: the integration, and reading Suricata/Zeek JSON |
| `local_rules.xml` | Raises severe Suricata alerts, repeated alerts and Zeek scans to level 10+ |

## Setup

1. **Wazuh:** install it with the official all-in-one installer or Docker (see documentation.wazuh.com, "Quickstart"). That gives you the manager, the indexer and the dashboard.
2. **Suricata and Zeek:** run them on the sensor that gets the mirrored traffic, and put a Wazuh agent on it. Add the `<localfile>` blocks from `ossec-integration.xml` to the agent's `ossec.conf`.
3. **TheHive:** run it with the official Docker setup (docs.strangebee.com) and create an API key for a "netops" user that may create alerts.
4. **OPNsense:**
   - Create a Host alias `netops_blocked`.
   - Add a WAN rule "block source netops_blocked" at the top.
   - Create an API key and secret under System > Access > Users.
5. **AbuseIPDB:** a free API key (1000 lookups a day).
6. **On the Wazuh manager:**
   - Fill in `/etc/netops/env` from `../env.example`.
   - Run `sh install.sh`.
   - Add the integration block and the rules.
   - Run `systemctl restart wazuh-manager`.
7. **Test with a saved alert:**
   ```bash
   NETOPS_DRY_RUN=true python3 custom-netops-soar.py /path/to/alert.json
   ```

## Safety built in

- No AbuseIPDB key means it never blocks. It only creates the TheHive alert for a person.
- Private ranges and the allowlist are never blocked, and each IP is blocked at most once a day.
- Every block is visible in TheHive with the tag `auto-blocked`. That makes it easy to review and undo in the OPNsense alias.

Prefer drag-and-drop over Python? **Shuffle** (shuffler.io) can run the same steps as a visual workflow. Wazuh sends to Shuffle with `<name>shuffle</name>` and a hook URL. This script is the code version of the same idea.
