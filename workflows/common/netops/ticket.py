"""Open a ticket in whichever system is configured (first match wins).

  Jira:    JIRA_URL, JIRA_USER (email), JIRA_TOKEN, JIRA_PROJECT (key, e.g. NET)
  GitLab:  GITLAB_URL, GITLAB_TOKEN, GITLAB_PROJECT_ID
  TOPdesk: TOPDESK_URL, TOPDESK_USER, TOPDESK_APP_PASSWORD

The same `key` (e.g. "block:203.0.113.7") opens at most one ticket per
TICKET_COOLDOWN seconds (default 1 day), so an alert storm is one ticket.
"""

from __future__ import annotations

import os

from .http import HttpError, basic_auth, request
from .safety import RateLimiter


def open_ticket(key: str, title: str, details: str) -> str | None:
    cooldown = int(os.environ.get("TICKET_COOLDOWN", "86400"))
    if not RateLimiter("tickets", 1, cooldown).allow(key):
        print(f"[ticket] already opened one for {key} recently, skipping")
        return None
    try:
        if os.environ.get("JIRA_URL"):
            return _jira(title, details)
        if os.environ.get("GITLAB_URL"):
            return _gitlab(title, details)
        if os.environ.get("TOPDESK_URL"):
            return _topdesk(title, details)
    except (HttpError, OSError) as exc:
        print(f"[ticket] could not create ticket: {exc}")
        return None
    print(f"[ticket] no ticket system configured. Would open: {title}")
    return None


def _jira(title: str, details: str) -> str:
    url = os.environ["JIRA_URL"].rstrip("/")
    res = request("POST", f"{url}/rest/api/2/issue",
                  headers={"Authorization": basic_auth(os.environ["JIRA_USER"], os.environ["JIRA_TOKEN"])},
                  body={"fields": {"project": {"key": os.environ["JIRA_PROJECT"]},
                                   "summary": title[:250], "description": details,
                                   "issuetype": {"name": os.environ.get("JIRA_ISSUE_TYPE", "Task")}}})
    print(f"[ticket] Jira {res['key']}")
    return res["key"]


def _gitlab(title: str, details: str) -> str:
    url = os.environ["GITLAB_URL"].rstrip("/")
    res = request("POST", f"{url}/api/v4/projects/{os.environ['GITLAB_PROJECT_ID']}/issues",
                  headers={"PRIVATE-TOKEN": os.environ["GITLAB_TOKEN"]},
                  body={"title": title[:250], "description": details, "labels": "netops,automated"})
    print(f"[ticket] GitLab issue #{res['iid']}")
    return str(res["iid"])


def _topdesk(title: str, details: str) -> str:
    url = os.environ["TOPDESK_URL"].rstrip("/")
    res = request("POST", f"{url}/tas/api/incidents",
                  headers={"Authorization": basic_auth(os.environ["TOPDESK_USER"],
                                                       os.environ["TOPDESK_APP_PASSWORD"])},
                  body={"briefDescription": title[:80], "request": details})
    print(f"[ticket] TOPdesk {res.get('number')}")
    return str(res.get("number"))
