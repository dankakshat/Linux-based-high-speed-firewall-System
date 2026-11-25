"""Webhook alert dispatcher for XDP-Engine."""

from __future__ import annotations

import os

import requests

from .models import Alert


class Notifier:
    """Sends structured JSON alert notifications to a configured webhook."""

    def __init__(self, webhook_url: str | None = None, timeout: float = 3.0) -> None:
        self.webhook_url = (
            webhook_url if webhook_url is not None else os.environ.get("XDP_WEBHOOK_URL", "")
        ).strip()
        self.timeout = timeout

    def notify(self, alert: Alert) -> bool:
        """Dispatch *alert* if a webhook URL is configured. Returns True on success."""
        if not self.webhook_url:
            return False

        payload = {
            "rule": alert.rule_name,
            "src_ip": alert.src_ip,
            "severity": alert.severity,
            "mitre": alert.mitre,
            "action": alert.action,
            "enforced": alert.enforced,
            "block_seconds": alert.block_seconds,
            "details": alert.details,
            "timestamp": alert.timestamp,
        }
        try:
            resp = requests.post(self.webhook_url, json=payload, timeout=self.timeout)
            return 200 <= resp.status_code < 300
        except requests.RequestException:
            return False
