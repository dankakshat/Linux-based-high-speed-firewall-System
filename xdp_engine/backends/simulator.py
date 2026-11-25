"""Pure-Python packet filter & telemetry simulator backend.

Runs identically on Windows, macOS, and Linux without root privileges while
modeling XDP drop/pass counters, blocked/allowed IP tables, TTL expiration,
port-scan sweep detection, and volumetric SYN flood detection.
"""

from __future__ import annotations

from collections import defaultdict, deque
import threading
import time

from ..models import BlockedIP, EngineStats, OperatingMode, SecurityEvent
from .base import PacketBackend


class SimulatorBackend(PacketBackend):
    """Cross-platform pure-Python packet filtering simulator."""

    name = "python-sim"

    def __init__(self, scan_port_threshold: int = 12, syn_flood_threshold: int = 120) -> None:
        self._interface = "sim0"
        self._mode = OperatingMode.DETECT
        self._attached = False
        self._lock = threading.Lock()
        self._blocked: dict[str, BlockedIP] = {}
        self._allowed: set[str] = set()
        self._stats = EngineStats()
        self._pending_events: list[SecurityEvent] = []
        self._scan_ports: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._syn_times: dict[str, deque[float]] = defaultdict(deque)
        self._scan_alerted: dict[str, float] = {}
        self._flood_alerted: dict[str, float] = {}
        self._scan_port_threshold = scan_port_threshold
        self._syn_flood_threshold = syn_flood_threshold
        self._last_dropped = 0
        self._last_rate_ts = time.time()

    def attach(self, interface: str) -> None:
        self._interface = interface or "sim0"
        self._attached = True

    def detach(self) -> None:
        self._attached = False

    def set_mode(self, mode: OperatingMode) -> None:
        with self._lock:
            self._mode = mode

    def block_ip(self, ip: str, ttl_seconds: int = 600, reason: str = "manual") -> None:
        now = time.time()
        expires_at = 0.0 if ttl_seconds <= 0 else now + ttl_seconds
        with self._lock:
            existing = self._blocked.get(ip)
            hits = existing.hits if existing else 0
            self._blocked[ip] = BlockedIP(
                ip=ip,
                reason=reason,
                blocked_at=now,
                expires_at=expires_at,
                hits=hits,
                enforced=(self._mode == OperatingMode.ENFORCE),
            )

    def unblock_ip(self, ip: str) -> bool:
        with self._lock:
            return self._blocked.pop(ip, None) is not None

    def allow_ip(self, ip: str) -> None:
        with self._lock:
            self._allowed.add(ip)

    def unallow_ip(self, ip: str) -> bool:
        with self._lock:
            if ip in self._allowed:
                self._allowed.remove(ip)
                return True
            return False

    def is_allowed(self, ip: str) -> bool:
        """Return True if *ip* is whitelisted."""
        with self._lock:
            return ip in self._allowed

    def list_blocked(self) -> list[BlockedIP]:
        now = time.time()
        with self._lock:
            items = [
                entry
                for entry in self._blocked.values()
                if entry.expires_at == 0 or now < entry.expires_at
            ]
        return sorted(items, key=lambda item: item.blocked_at, reverse=True)

    def process_packet(
        self,
        src_ip: str,
        protocol: str = "TCP",
        dst_port: int = 80,
        syn_only: bool = False,
        count: int = 1,
    ) -> bool:
        """Simulate packet evaluation at the XDP hook.

        Returns True if the packet is passed, False if dropped.
        """
        now = time.time()
        proto = protocol.upper()
        with self._lock:
            if proto == "TCP":
                self._stats.tcp += count
            elif proto == "UDP":
                self._stats.udp += count
            elif proto == "ICMP":
                self._stats.icmp += count

            if src_ip in self._allowed:
                self._stats.passed += count
                return True

            entry = self._blocked.get(src_ip)
            if entry is not None and (entry.expires_at == 0 or now < entry.expires_at):
                entry.hits += count
                if self._mode == OperatingMode.ENFORCE:
                    self._stats.dropped += count
                    return False

            if proto == "TCP" and syn_only:
                self._track_syn_anomalies(src_ip, dst_port, count, now)

            self._stats.passed += count
            return True

    def _track_syn_anomalies(
        self, src_ip: str, dst_port: int, count: int, now: float
    ) -> None:
        window = 5.0
        ports_q = self._scan_ports[src_ip]
        ports_q.append((now, dst_port))
        while ports_q and now - ports_q[0][0] > window:
            ports_q.popleft()

        unique_ports = {p for _, p in ports_q}
        if (
            len(unique_ports) >= self._scan_port_threshold
            and now - self._scan_alerted.get(src_ip, 0.0) > window
        ):
            self._scan_alerted[src_ip] = now
            self._pending_events.append(
                SecurityEvent(
                    event_type="port_scan",
                    src_ip=src_ip,
                    timestamp=now,
                    target=f"ports:{len(unique_ports)}",
                    payload=f"SYN sweep across {len(unique_ports)} ports",
                    metadata={"unique_ports": len(unique_ports)},
                )
            )

        syn_q = self._syn_times[src_ip]
        for _ in range(min(count, self._syn_flood_threshold + 10)):
            syn_q.append(now)
        while syn_q and now - syn_q[0] > window:
            syn_q.popleft()

        if (
            len(syn_q) >= self._syn_flood_threshold
            and now - self._flood_alerted.get(src_ip, 0.0) > window
        ):
            self._flood_alerted[src_ip] = now
            self._pending_events.append(
                SecurityEvent(
                    event_type="syn_flood",
                    src_ip=src_ip,
                    timestamp=now,
                    target=f"port:{dst_port}",
                    payload=f"High-rate SYN burst ({len(syn_q)} SYNs in 5s)",
                    metadata={"syn_count": len(syn_q)},
                )
            )

    def get_stats(self) -> EngineStats:
        now = time.time()
        with self._lock:
            dt = max(0.2, now - self._last_rate_ts)
            rate = max(0.0, (self._stats.dropped - self._last_dropped) / dt)
            self._last_dropped = self._stats.dropped
            self._last_rate_ts = now
            return EngineStats(
                dropped=self._stats.dropped,
                passed=self._stats.passed,
                tcp=self._stats.tcp,
                udp=self._stats.udp,
                icmp=self._stats.icmp,
                drop_rate_pps=round(rate, 2),
            )

    def poll_events(self) -> list[SecurityEvent]:
        with self._lock:
            events = list(self._pending_events)
            self._pending_events.clear()
        return events

    def purge_expired(self) -> list[str]:
        now = time.time()
        expired: list[str] = []
        with self._lock:
            for ip, entry in list(self._blocked.items()):
                if entry.expires_at > 0 and now >= entry.expires_at:
                    expired.append(ip)
                    del self._blocked[ip]
        return expired
