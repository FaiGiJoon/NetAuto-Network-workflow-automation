"""Send a short message to the channels that are configured.

  TEAMS_WEBHOOK_URL                      Teams incoming webhook / Workflows URL
  SLACK_WEBHOOK_URL                      Slack incoming webhook
  TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID  Telegram bot
None configured = the message is only printed.
"""

from __future__ import annotations

import os

from .http import HttpError, request


def send(text: str) -> list[str]:
    sent = []
    print(f"[notify] {text}")
    try:
        if url := os.environ.get("TEAMS_WEBHOOK_URL"):
            request("POST", url, body={"text": text})
            sent.append("teams")
        if url := os.environ.get("SLACK_WEBHOOK_URL"):
            request("POST", url, body={"text": text})
            sent.append("slack")
        token, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
        if token and chat:
            request("POST", f"https://api.telegram.org/bot{token}/sendMessage",
                    body={"chat_id": chat, "text": text})
            sent.append("telegram")
    except (HttpError, OSError) as exc:
        print(f"[notify] sending failed: {exc}")
    return sent
