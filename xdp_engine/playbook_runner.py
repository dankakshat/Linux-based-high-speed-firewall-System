"""Automated SOAR playbook runner and safety guardrails."""

from __future__ import annotations

from pathlib import Path
import yaml

from .backends.base import PacketBackend
from .models import Alert, OperatingMode
from .notifier import Notifier
from .storage import Storage


class PlaybookRunner:
    """Executes YAML-defined response playbooks with self-lockout protection."""

    def __init__(
        self,
        playbooks_path: str | Path,
        backend: PacketBackend,
        storage: Storage,
        notifier: Notifier,
        guardrail_ips: set[str] | None = None,
    ) -> None:
        self.playbooks_path = Path(playbooks_path)
        self.backend = backend
        self.storage = storage
        self.notifier = notifier
        self.guardrail_ips: set[str] = set(guardrail_ips or ())
        self.mode = OperatingMode.DETECT
        self.playbooks: dict[str, list[str]] = {}
        self.load_playbooks()

    def load_playbooks(self) -> None:
        """Load playbook definitions from YAML."""
        if not self.playbooks_path.exists():
            self.playbooks = {}
            return
        raw = yaml.safe_load(self.playbooks_path.read_text(encoding="utf-8")) or {}
        parsed: dict[str, list[str]] = {}
        for rule_name, steps in raw.items():
            parsed[rule_name] = [s["step"] for s in steps if isinstance(s, dict) and "step" in s]
        self.playbooks = parsed

    def set_mode(self, mode: OperatingMode) -> None:
        """Update operating mode across runner and packet backend."""
        self.mode = mode
        self.backend.set_mode(mode)

    def add_whitelist_ip(self, ip: str) -> None:
        """Protect an IP from ever being blocked."""
        self.guardrail_ips.add(ip)
        self.backend.allow_ip(ip)
        self.backend.unblock_ip(ip)

    def remove_whitelist_ip(self, ip: str) -> bool:
        """Remove an IP from the whitelist."""
        self.guardrail_ips.discard(ip)
        return self.backend.unallow_ip(ip)

    def execute(self, alert: Alert) -> bool:
        """Run the playbook associated with *alert*. Returns True if blocked."""
        steps = self.playbooks.get(alert.rule_name, ["enrich", "block", "record"])
        blocked = False

        if "enrich" in steps:
            alert.details = f"{alert.details} | mode={self.mode.value}".strip(" |")

        if "block" in steps and alert.action == "block":
            if alert.src_ip in self.guardrail_ips:
                self.storage.add_feed_event(
                    "warn",
                    "GUARDRAIL",
                    f"Skipped blocking whitelisted/local IP {alert.src_ip} ({alert.rule_name})",
                )
            elif self.mode == OperatingMode.ENFORCE:
                self.backend.block_ip(
                    alert.src_ip,
                    ttl_seconds=alert.block_seconds,
                    reason=alert.rule_name,
                )
                alert.enforced = True
                blocked = True
                self.storage.add_feed_event(
                    "critical",
                    "PLAYBOOK",
                    f"ENFORCED drop on {alert.src_ip} for {alert.block_seconds}s ({alert.rule_name})",
                )
            else:
                self.storage.add_feed_event(
                    "info",
                    "DETECT",
                    f"Would block {alert.src_ip} for {alert.block_seconds}s ({alert.rule_name})",
                )

        if "notify" in steps:
            self.notifier.notify(alert)

        if "record" in steps:
            self.storage.record_alert(alert)
            if not blocked and self.mode == OperatingMode.ENFORCE and alert.src_ip not in self.guardrail_ips:
                self.storage.add_feed_event("warn", "ALERT", f"{alert.rule_name}: {alert.src_ip}")

        return blocked
