#!/usr/bin/env python3
"""Wazuh integration: the "SOAR" step of the SOC workflow.

Wazuh calls this for every alert at or above the level set in ossec.conf:
    custom-netops-soar <alert_file> <api_key> <hook_url>

For an alert with a source IP it:
  1. looks the IP up on AbuseIPDB (reputation 0-100)
  2. score >= ABUSE_THRESHOLD (default 75): adds the IP to an OPNsense alias
     that a block rule uses
  3. opens an alert in TheHive with the IP as observable, so an analyst can
     turn it into a case
  4. sends a notification

Without AbuseIPDB it never blocks automatically, it only opens the TheHive alert.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[1] / "common"))
sys.path.insert(0, "/var/ossec/integrations/netops-common")   # where install.sh copies the library

from netops import notify  # noqa: E402
from netops.http import HttpError, basic_auth, request, tls_context  # noqa: E402
from netops.safety import RateLimiter, dry_run, may_block  # noqa: E402


def source_ip(alert: dict) -> str | None:
    data = alert.get("data") or {}
    return data.get("src_ip") or data.get("srcip") or (data.get("flow") or {}).get("src_ip")


def abuse_score(ip: str) -> int | None:
    key = os.environ.get("ABUSEIPDB_KEY")
    if not key:
        return None
    base = os.environ.get("ABUSEIPDB_URL", "https://api.abuseipdb.com").rstrip("/")
    res = request("GET", f"{base}/api/v2/check",
                  params={"ipAddress": ip, "maxAgeInDays": 90}, headers={"Key": key})
    return int(res["data"]["abuseConfidenceScore"])


def opnsense_block(ip: str) -> str:
    url = os.environ["OPNSENSE_URL"].rstrip("/")
    alias = os.environ.get("OPNSENSE_ALIAS", "netops_blocked")
    res = request("POST", f"{url}/api/firewall/alias_util/add/{alias}", body={"address": ip},
                  headers={"Authorization": basic_auth(os.environ["OPNSENSE_KEY"], os.environ["OPNSENSE_SECRET"])},
                  context=tls_context(os.environ.get("OPNSENSE_VERIFY_TLS", "true") != "false"))
    return str(res.get("status", res))


def thehive_alert(alert: dict, ip: str, score, blocked: bool) -> str | None:
    url, key = os.environ.get("THEHIVE_URL"), os.environ.get("THEHIVE_KEY")
    if not url or not key:
        return None
    rule = alert.get("rule") or {}
    level = int(rule.get("level", 0))
    body = {
        "type": "wazuh", "source": "netops-soar",
        "sourceRef": str(alert.get("id", ""))[:64] or ip,
        "title": f"{rule.get('description', 'Wazuh alert')} from {ip}"[:250],
        "description": (f"Agent: {(alert.get('agent') or {}).get('name')}\nRule {rule.get('id')} level {level}\n"
                        f"AbuseIPDB score: {score if score is not None else 'not checked'}\n"
                        f"Blocked on firewall: {'yes' if blocked else 'no'}\n\n"
                        f"```\n{json.dumps(alert, indent=2)[:6000]}\n```"),
        "severity": 3 if level >= 12 else 2 if level >= 8 else 1,
        "tags": ["netops", "auto-blocked" if blocked else "review"],
        "observables": [{"dataType": "ip", "data": ip}],
    }
    res = request("POST", f"{url.rstrip('/')}/api/v1/alert", body=body,
                  headers={"Authorization": f"Bearer {key}"})
    return res.get("_id")


def handle(alert: dict) -> dict:
    ip = source_ip(alert)
    out = {"ip": ip, "score": None, "blocked": False, "thehive": None}
    if not ip:
        return out
    ok, why = may_block(ip)
    if not ok:
        print(f"[skip] {why}")
        return out
    threshold = int(os.environ.get("ABUSE_THRESHOLD", "75"))
    try:
        out["score"] = abuse_score(ip)
    except (HttpError, OSError) as exc:
        print(f"[abuseipdb] lookup failed: {exc}")
    if out["score"] is not None and out["score"] >= threshold:
        if not RateLimiter("soc-blocks", 1, 86400).allow(ip):
            print(f"[skip] {ip} was already blocked today")
        elif dry_run() or not os.environ.get("OPNSENSE_URL"):
            print(f"[dry-run] would block {ip} on OPNsense (score {out['score']})")
            out["blocked"] = True
        else:
            try:
                print(f"[opnsense] {opnsense_block(ip)}")
                out["blocked"] = True
            except (HttpError, OSError) as exc:
                notify.send(f"netops SOC: failed to block {ip} on OPNsense: {exc}")
    try:
        out["thehive"] = thehive_alert(alert, ip, out["score"], out["blocked"])
    except (HttpError, OSError) as exc:
        print(f"[thehive] failed: {exc}")
    rule = (alert.get("rule") or {}).get("description", "alert")
    notify.send(f"netops SOC: {rule} from {ip}, AbuseIPDB {out['score']}, "
                f"{'BLOCKED' if out['blocked'] else 'not blocked, needs review'}")
    return out


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    alert = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    print(json.dumps(handle(alert)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
