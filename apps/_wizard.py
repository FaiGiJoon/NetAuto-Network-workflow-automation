"""Setup questions that every app shares."""

from __future__ import annotations

from _runtime import Asker, default_state_dir, step

DEFAULT_ALLOWLIST = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8"


def ask_safety(a: Asker) -> dict:
    step("Safety")
    print("   Start in dry-run mode: the app only says what it would do. Turn it off once you trust it.")
    dry = "true" if a.yes("Start in dry-run mode?", a.current.get("NETOPS_DRY_RUN", "true") != "false") else "false"
    allow = a.ask("NETOPS_ALLOWLIST", "Networks that may NEVER be blocked (comma-separated)", DEFAULT_ALLOWLIST)
    return {"NETOPS_DRY_RUN": dry, "NETOPS_ALLOWLIST": allow,
            "NETOPS_STATE_DIR": a.current.get("NETOPS_STATE_DIR") or str(default_state_dir())}


def ask_mikrotik(a: Asker, what: str = "the MikroTik") -> dict:
    step(f"MikroTik REST API ({what})")
    print("   Needs: /ip service enable www-ssl, and a user with the rest-api, read and write policies.")
    return {
        "MIKROTIK_HOST": a.ask("MIKROTIK_HOST", "Router IP or name", required=True),
        "MIKROTIK_USER": a.ask("MIKROTIK_USER", "User", "netops", required=True),
        "MIKROTIK_PASSWORD": a.ask("MIKROTIK_PASSWORD", "Password", secret=True, required=True),
        "MIKROTIK_VERIFY_TLS": "true" if a.yes("Check the router's TLS certificate? (say no only for a lab with a self-signed one)",
                                                a.current.get("MIKROTIK_VERIFY_TLS", "true") != "false") else "false",
    }


def ask_notifications(a: Asker) -> dict:
    step("Notifications (press Enter to skip any)")
    return {
        "TEAMS_WEBHOOK_URL": a.ask("TEAMS_WEBHOOK_URL", "Teams webhook URL"),
        "SLACK_WEBHOOK_URL": a.ask("SLACK_WEBHOOK_URL", "Slack webhook URL"),
        "TELEGRAM_BOT_TOKEN": a.ask("TELEGRAM_BOT_TOKEN", "Telegram bot token", secret=True),
        "TELEGRAM_CHAT_ID": a.ask("TELEGRAM_CHAT_ID", "Telegram chat ID"),
    }


def ask_tickets(a: Asker) -> dict:
    step("Tickets (press Enter to skip)")
    kind = a.ask("NETOPS_TICKETS", "Ticket system: jira, gitlab, topdesk or none", "none").lower()
    out = {"NETOPS_TICKETS": kind}
    if kind == "jira":
        out |= {"JIRA_URL": a.ask("JIRA_URL", "Jira URL", required=True),
                "JIRA_USER": a.ask("JIRA_USER", "Jira user (email)", required=True),
                "JIRA_TOKEN": a.ask("JIRA_TOKEN", "Jira API token", secret=True, required=True),
                "JIRA_PROJECT": a.ask("JIRA_PROJECT", "Jira project key", "NET")}
    elif kind == "gitlab":
        out |= {"GITLAB_URL": a.ask("GITLAB_URL", "GitLab URL", "https://gitlab.com"),
                "GITLAB_TOKEN": a.ask("GITLAB_TOKEN", "GitLab token (api scope)", secret=True, required=True),
                "GITLAB_PROJECT_ID": a.ask("GITLAB_PROJECT_ID", "Project ID", required=True)}
    elif kind == "topdesk":
        out |= {"TOPDESK_URL": a.ask("TOPDESK_URL", "TOPdesk URL", required=True),
                "TOPDESK_USER": a.ask("TOPDESK_USER", "TOPdesk user", required=True),
                "TOPDESK_APP_PASSWORD": a.ask("TOPDESK_APP_PASSWORD", "TOPdesk application password", secret=True, required=True)}
    return out
