# 6. Home lab: Uptime Kuma + ntopng + n8n

Light, visual and quick to build. Uptime Kuma checks whether everything is up, ntopng shows live who is using the network, and an n8n workflow restarts a dead camera or access point through PoE and sends you a Telegram message.

```
Uptime Kuma ──webhook──> n8n: Find PoE port ──> down and has a port? ──yes──> MikroTik REST power-cycle ──> Telegram "restarted"
                                                                     └─no───> Telegram "down / back up"
ntopng <── mirrored traffic (live top talkers, protocols, flows)
```

| File | What it does |
| --- | --- |
| `docker-compose.yml` | Uptime Kuma, n8n, ntopng and Redis |
| `n8n-poe-restart-workflow.json` | The n8n workflow, ready to import |
| `.env.example` | Secrets n8n reads (MikroTik and Telegram) |

## Setup

1. Run `cp .env.example .env` and fill it in. For the MikroTik line, use `echo -n 'netops:password' | base64`. Then run `docker compose up -d`.
2. **n8n** (port 5678):
   - Create the owner account.
   - Go to Workflows > Import from file and choose `n8n-poe-restart-workflow.json`.
   - In the **Find PoE port** node, change the table so it lists your devices and their switch ports.
   - Activate the workflow.
3. **Uptime Kuma** (port 3001):
   - Add a monitor per device, and give each one the same name as in the n8n table.
   - Under Settings > Notifications, add a **Webhook** notification with the URL `http://n8n:5678/webhook/uptime-kuma` and body type "application/json". Turn it on for the monitors.
4. **ntopng** (port 3002): mirror a switch port to the NIC in `NTOPNG_INTERFACE`, the same way as in workflow 4.

## Notes

- n8n's node versions change over time. After importing, open each node once and check that the fields still look right.
- MikroTik with a self-signed certificate: either install a proper certificate, or turn on "Ignore SSL issues" in the PoE node (lab only).
- There is no restart limit in this n8n version. To add one, put an n8n "Rate limit" step in front of it, or use workflow 1 or 3, which have the limit built in.
