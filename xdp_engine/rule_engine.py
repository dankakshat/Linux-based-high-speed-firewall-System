"""YAML-driven threshold and sequence correlation rule engine."""

from __future__ import annotations

from collections import defaultdict, deque
from pathlib import Path
import re
import threading
from urllib.parse import unquote
import yaml

from .models import Alert, Rule, SecurityEvent


class RuleEngine:
    """Evaluates incoming SecurityEvents against threshold and sequence rules."""

    def __init__(self, rules_path: str | Path) -> None:
        self.rules_path = Path(rules_path)
        self.rules: list[Rule] = []
        self._lock = threading.Lock()
        self._threshold_hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._sequence_history: dict[str, deque[tuple[str, float]]] = defaultdict(deque)
        self._compiled_patterns: dict[str, list[re.Pattern[str]]] = {}
        self.load_rules()

    def load_rules(self) -> None:
        """Load or reload rules from YAML."""
        if not self.rules_path.exists():
            self.rules = []
            return

        raw = yaml.safe_load(self.rules_path.read_text(encoding="utf-8")) or []
        loaded: list[Rule] = []
        compiled: dict[str, list[re.Pattern[str]]] = {}

        for item in raw:
            mitre_val = item.get("mitre", [])
            mitre_list = [mitre_val] if isinstance(mitre_val, str) else list(mitre_val)
            patterns = list(item.get("patterns", []))
            rule = Rule(
                name=item["name"],
                rule_type=item.get("type", "threshold"),
                severity=item.get("severity", "medium"),
                mitre=mitre_list,
                action=item.get("action", "block"),
                block_seconds=int(item.get("block_seconds", 600)),
                match_type=item.get("match_type", ""),
                threshold=int(item.get("threshold", 1)),
                window_seconds=int(item.get("window_seconds", 60)),
                patterns=patterns,
                steps=list(item.get("steps", [])),
                within_seconds=int(item.get("within_seconds", 300)),
            )
            loaded.append(rule)
            if patterns:
                compiled[rule.name] = [re.compile(p, re.IGNORECASE) for p in patterns]

        with self._lock:
            self.rules = loaded
            self._compiled_patterns = compiled

    def evaluate(self, event: SecurityEvent) -> list[Alert]:
        """Evaluate a single SecurityEvent and return any triggered Alerts."""
        alerts: list[Alert] = []
        with self._lock:
            history = self._sequence_history[event.src_ip]
            history.append((event.event_type, event.timestamp))
            # Retain up to 1 hour of sequence history per IP.
            cutoff = event.timestamp - 3600
            while history and history[0][1] < cutoff:
                history.popleft()

            for rule in self.rules:
                if rule.rule_type == "threshold":
                    alert = self._eval_threshold(rule, event)
                    if alert is not None:
                        alerts.append(alert)
                elif rule.rule_type == "sequence":
                    alert = self._eval_sequence(rule, event, history)
                    if alert is not None:
                        alerts.append(alert)
        return alerts

    def _eval_threshold(self, rule: Rule, event: SecurityEvent) -> Alert | None:
        if event.event_type != rule.match_type:
            return None

        patterns = self._compiled_patterns.get(rule.name)
        if patterns:
            haystack = f"{event.payload} {unquote(event.payload)}"
            if not any(pat.search(haystack) for pat in patterns):
                return None

        key = (rule.name, event.src_ip)
        hits = self._threshold_hits[key]
        hits.append(event.timestamp)
        window_start = event.timestamp - rule.window_seconds
        while hits and hits[0] < window_start:
            hits.popleft()

        if len(hits) >= rule.threshold:
            hit_count = len(hits)
            hits.clear()
            return Alert(
                rule_name=rule.name,
                src_ip=event.src_ip,
                severity=rule.severity,
                mitre=list(rule.mitre),
                action=rule.action,
                block_seconds=rule.block_seconds,
                timestamp=event.timestamp,
                details=f"Matched {hit_count}x {rule.match_type} in {rule.window_seconds}s ({event.target or 'net'})",
            )
        return None

    def _eval_sequence(
        self,
        rule: Rule,
        event: SecurityEvent,
        history: deque[tuple[str, float]],
    ) -> Alert | None:
        if not rule.steps or event.event_type != rule.steps[-1]:
            return None

        window_start = event.timestamp - rule.within_seconds
        step_idx = 0
        for ev_type, ev_ts in history:
            if ev_ts < window_start:
                continue
            if ev_type == rule.steps[step_idx]:
                step_idx += 1
                if step_idx == len(rule.steps):
                    return Alert(
                        rule_name=rule.name,
                        src_ip=event.src_ip,
                        severity=rule.severity,
                        mitre=list(rule.mitre),
                        action=rule.action,
                        block_seconds=rule.block_seconds,
                        timestamp=event.timestamp,
                        details=f"Correlated sequence {' -> '.join(rule.steps)} within {rule.within_seconds}s",
                    )
        return None
