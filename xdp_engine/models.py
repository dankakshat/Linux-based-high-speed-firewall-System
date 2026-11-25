"""Core data models for XDP-Engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import time
from typing import Any


class OperatingMode(str, Enum):
    """Firewall operating mode."""

    DETECT = "detect"
    ENFORCE = "enforce"


@dataclass(slots=True)
class SecurityEvent:
    """Normalized event emitted by log detectors or packet telemetry."""

    event_type: str
    src_ip: str
    timestamp: float = field(default_factory=time.time)
    target: str = ""
    payload: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Rule:
    """Detection rule parsed from rules.yaml."""

    name: str
    rule_type: str  # "threshold" or "sequence"
    severity: str = "medium"
    mitre: list[str] = field(default_factory=list)
    action: str = "block"
    block_seconds: int = 600
    # Threshold rule attributes
    match_type: str = ""
    threshold: int = 1
    window_seconds: int = 60
    patterns: list[str] = field(default_factory=list)
    # Sequence rule attributes
    steps: list[str] = field(default_factory=list)
    within_seconds: int = 300


@dataclass(slots=True)
class Alert:
    """Alert generated when a rule matches."""

    rule_name: str
    src_ip: str
    severity: str
    mitre: list[str]
    action: str
    block_seconds: int
    timestamp: float = field(default_factory=time.time)
    details: str = ""
    enforced: bool = False


@dataclass(slots=True)
class BlockedIP:
    """Active block entry tracked in kernel/backend map."""

    ip: str
    reason: str
    blocked_at: float
    expires_at: float  # 0 means permanent
    hits: int = 0
    enforced: bool = True

    @property
    def remaining_seconds(self) -> int:
        """Seconds left before expiration, or -1 for permanent blocks."""
        if self.expires_at <= 0:
            return -1
        return max(0, int(self.expires_at - time.time()))


@dataclass(slots=True)
class EngineStats:
    """Packet and protocol counters."""

    dropped: int = 0
    passed: int = 0
    tcp: int = 0
    udp: int = 0
    icmp: int = 0
    drop_rate_pps: float = 0.0
