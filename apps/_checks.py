"""Connection checks and one-time router setup used by several apps."""

from __future__ import annotations

import os

from _runtime import fail, ok, setup_import_path, warn

setup_import_path()

from netops.http import HttpError, basic_auth, request, tls_context  # noqa: E402
from netops.mikrotik import RouterOS  # noqa: E402


def check_mikrotik(host: str | None = None) -> RouterOS | None:
    try:
        router = RouterOS.from_env(host=host)
        info = router.get("system/resource")
        ok(f"MikroTik {router.host}: {info.get('board-name', '?')}, RouterOS {info.get('version', '?')}")
        return router
    except KeyError as exc:
        fail(f"MikroTik setting missing: {exc}")
    except HttpError as exc:
        fail(f"MikroTik answered with an error: {exc} (check user, password and the rest-api policy)")
    except OSError as exc:
        fail(f"MikroTik not reachable: {exc} (is www-ssl enabled? right IP? TLS certificate?)")
    return None


def ensure_raw_drop_rule(router: RouterOS, list_name: str, comment: str) -> str:
    """Adds 'drop everything from <list>' to the raw table, once. Returns added/exists."""
    rules = router.get("ip/firewall/raw", comment=comment) or []
    if rules:
        return "exists"
    router.create("ip/firewall/raw", {"chain": "prerouting", "src-address-list": list_name,
                                      "action": "drop", "comment": comment})
    return "added"


def check_notifications() -> None:
    channels = [n for n, k in (("Teams", "TEAMS_WEBHOOK_URL"), ("Slack", "SLACK_WEBHOOK_URL"),
                               ("Telegram", "TELEGRAM_BOT_TOKEN")) if os.environ.get(k)]
    if channels:
        ok(f"notifications: {', '.join(channels)}")
    else:
        warn("no notification channel set: messages are only printed")


def check_tickets() -> None:
    for name, key in (("Jira", "JIRA_URL"), ("GitLab", "GITLAB_URL"), ("TOPdesk", "TOPDESK_URL")):
        if os.environ.get(key):
            ok(f"tickets go to {name}")
            return
    warn("no ticket system set: tickets are only printed")


def check_http(label: str, method: str, url: str, headers: dict | None = None, verify: bool = True) -> bool:
    try:
        request(method, url, headers=headers or {}, context=tls_context(verify) if url.startswith("https") else None)
        ok(f"{label} reachable")
        return True
    except HttpError as exc:
        fail(f"{label}: {exc}")
    except OSError as exc:
        fail(f"{label} not reachable: {exc}")
    return False


__all__ = ["check_mikrotik", "ensure_raw_drop_rule", "check_notifications", "check_tickets",
           "check_http", "basic_auth"]
