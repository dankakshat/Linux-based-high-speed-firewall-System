"""Abstract interface for kernel/user-space packet filtering backends."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import BlockedIP, EngineStats, OperatingMode, SecurityEvent


class PacketBackend(ABC):
    """Contract implemented by both Linux eBPF/XDP and Simulator backends."""

    name: str = "base"

    @abstractmethod
    def attach(self, interface: str) -> None:
        """Attach packet filter to *interface*."""

    @abstractmethod
    def detach(self) -> None:
        """Detach packet filter cleanly."""

    @abstractmethod
    def set_mode(self, mode: OperatingMode) -> None:
        """Switch between DETECT (audit) and ENFORCE (drop) modes."""

    @abstractmethod
    def block_ip(self, ip: str, ttl_seconds: int = 600, reason: str = "manual") -> None:
        """Insert or update a blocked IP entry with optional TTL (0 = permanent)."""

    @abstractmethod
    def unblock_ip(self, ip: str) -> bool:
        """Remove an IP from the drop table. Returns True if removed."""

    @abstractmethod
    def allow_ip(self, ip: str) -> None:
        """Add an IP to the permanent fast-pass whitelist."""

    @abstractmethod
    def unallow_ip(self, ip: str) -> bool:
        """Remove an IP from the whitelist. Returns True if removed."""

    @abstractmethod
    def list_blocked(self) -> list[BlockedIP]:
        """Return currently active blocked IP entries."""

    @abstractmethod
    def get_stats(self) -> EngineStats:
        """Return current packet and protocol statistics."""

    @abstractmethod
    def poll_events(self) -> list[SecurityEvent]:
        """Drain any pending network anomaly events (port scan, SYN flood)."""

    @abstractmethod
    def purge_expired(self) -> list[str]:
        """Remove expired temporary bans and return the unblocked IPs."""
